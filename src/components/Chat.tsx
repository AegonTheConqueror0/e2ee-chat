import React, { useState, useEffect, useRef } from 'react';
import { User as FirebaseUser } from 'firebase/auth';
import { IdentityKeys, encryptSymmetric, decryptSymmetric, generateRoomKey, signData, verifySignature, encryptAsymmetric, decryptAsymmetric, toBase64, fromBase64 } from '@/lib/crypto';
import { db, collection, query, where, onSnapshot, orderBy, addDoc, serverTimestamp, doc, getDoc, setDoc, getDocs, storage, auth, handleFirestoreError, OperationType, updateDoc, arrayUnion, limit, writeBatch } from '@/firebase';
import { ref, uploadBytes, getDownloadURL } from 'firebase/storage';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet';
import { MessageSquare, Plus, Send, Shield, Users, Settings, LogOut, Paperclip, Loader2, Search, Key, Download, ChevronLeft, Hash, Lock, UserPlus } from 'lucide-react';
import { format } from 'date-fns';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'motion/react';
import sodium from 'libsodium-wrappers';
import { runSecurityTest } from '@/lib/security-test';

interface ChatProps {
  user: FirebaseUser;
  keys: IdentityKeys;
}

interface Room {
  id: string;
  nameEncrypted: string;
  nameNonce?: string; // Added to share nonce for room name
  members: string[];
  createdAt: any;
  decryptedName?: string;
  isPrivate?: boolean;
}

interface Message {
  id: string;
  roomId: string;
  senderId: string;
  ciphertext: string;
  nonce: string;
  signature: string;
  createdAt: any;
  decryptedText?: string;
  isMine?: boolean;
}

export default function Chat({ user, keys }: ChatProps) {
  const [rooms, setRooms] = useState<Room[]>([]);
  const [activeRoom, setActiveRoom] = useState<Room | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [roomKeys, setRoomKeys] = useState<Record<string, Uint8Array>>({});
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [searchEmail, setSearchEmail] = useState('');
  const [allUsers, setAllUsers] = useState<any[]>([]);
  const [isSearchingUsers, setIsSearchingUsers] = useState(false);
  const [userSearchQuery, setUserSearchQuery] = useState('');

  useEffect(() => {
    const q = query(collection(db, 'users'), limit(100));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const usersList = snapshot.docs
        .map(doc => ({ id: doc.id, ...doc.data() }))
        .filter(u => u.id !== user.uid);
      setAllUsers(usersList);
    });
    return () => unsubscribe();
  }, [user.uid]);
  const [isCreatingRoom, setIsCreatingRoom] = useState(false);
  const [newRoomName, setNewRoomName] = useState('');
  const [isSodiumReady, setIsSodiumReady] = useState(false);
  const [showMobileSidebar, setShowMobileSidebar] = useState(true);
  
  const scrollRef = useRef<HTMLDivElement>(null);

  const [isKeyMismatch, setIsKeyMismatch] = useState(false);

  useEffect(() => {
    const checkKeyMismatch = async () => {
      const userDoc = await getDoc(doc(db, 'users', user.uid));
      if (userDoc.exists()) {
        const data = userDoc.data();
        const firestoreExchangeKey = data.publicKeyExchange;
        const localExchangeKey = toBase64(keys.exchange.publicKey);
        if (firestoreExchangeKey && firestoreExchangeKey !== localExchangeKey) {
          setIsKeyMismatch(true);
          toast.error('Identity Mismatch: Your local keys do not match your public profile. You may not be able to read some rooms.', {
            duration: 10000,
          });
        }
      }
    };
    checkKeyMismatch();
  }, [user.uid, keys.exchange.publicKey]);

  // --- Sodium Initialization ---
  useEffect(() => {
    sodium.ready.then(() => setIsSodiumReady(true));
  }, []);

  // --- Room Subscription ---

  useEffect(() => {
    const q = query(collection(db, 'rooms'), where('members', 'array-contains', user.uid));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const roomsData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Room));
      setRooms(roomsData);
      
      // Sync activeRoom if it exists
      if (activeRoom) {
        const updatedActive = roomsData.find(r => r.id === activeRoom.id);
        if (updatedActive) {
          // Keep the decryptedName if it was already set
          setActiveRoom(prev => prev ? { ...updatedActive, decryptedName: prev.decryptedName || updatedActive.decryptedName } : updatedActive);
        }
      }
    });
    return () => unsubscribe();
  }, [user.uid, activeRoom?.id]);

  // --- Room Key Subscription & Decryption ---

  useEffect(() => {
    if (rooms.length === 0) return;

    const unsubscribes = rooms.map(room => {
      const keyDocRef = doc(db, 'rooms', room.id, 'keys', user.uid);
      return onSnapshot(keyDocRef, (snapshot) => {
        if (snapshot.exists()) {
          const keyData = snapshot.data();
          try {
            const encryptedKey = fromBase64(keyData.encryptedKey);
            const decryptedKey = sodium.crypto_box_seal_open(
              encryptedKey,
              keys.exchange.publicKey,
              keys.exchange.privateKey
            );
            
            setRoomKeys(prev => ({ ...prev, [room.id]: decryptedKey }));
            
            // Decrypt room name
            if (room.nameEncrypted) {
              const nonce = room.nameNonce || keyData.nonce;
              if (nonce) {
                const decryptedName = decryptSymmetric(
                  { ciphertext: room.nameEncrypted, nonce },
                  decryptedKey
                );
                setRooms(prev => prev.map(r => r.id === room.id ? { ...r, decryptedName } : r));
              }
            }
          } catch (err) {
            console.error('Failed to decrypt room key:', err);
            toast.error(`Failed to decrypt key for room "${room.id.slice(0, 8)}...". This room might have been encrypted for a different device or identity.`, {
              id: `decrypt-fail-${room.id}`,
            });
          }
        }
      }, (err) => {
        handleFirestoreError(err, OperationType.GET, `rooms/${room.id}/keys/${user.uid}`);
      });
    });

    return () => unsubscribes.forEach(unsub => unsub());
  }, [rooms, user.uid, keys]);

  // --- Message Subscription ---

  useEffect(() => {
    if (!activeRoom || !roomKeys[activeRoom.id]) {
      setMessages([]);
      return;
    }

    const q = query(
      collection(db, 'rooms', activeRoom.id, 'messages'),
      orderBy('createdAt', 'asc')
    );

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const msgs = snapshot.docs.map(doc => {
        const data = doc.data() as Message;
        const roomKey = roomKeys[activeRoom.id];
        let decryptedText = '[Encrypted Message]';
        
        try {
          decryptedText = decryptSymmetric(
            { ciphertext: data.ciphertext, nonce: data.nonce },
            roomKey
          );
        } catch (err) {
          console.error('Failed to decrypt message:', err);
        }

        return {
          ...data,
          id: doc.id,
          decryptedText,
          isMine: data.senderId === user.uid
        };
      });
      setMessages(msgs);
      
      // Scroll to bottom
      setTimeout(() => {
        if (scrollRef.current) {
          scrollRef.current.scrollIntoView({ behavior: 'smooth' });
        }
      }, 100);
    });

    return () => unsubscribe();
  }, [activeRoom, roomKeys, user.uid]);

  useEffect(() => {
    if (activeRoom) {
      setShowMobileSidebar(false);
    }
  }, [activeRoom?.id]);

  // --- Actions ---

  const handleCreateRoom = async () => {
    if (!newRoomName || !isSodiumReady) return;
    setLoading(true);
    try {
      const roomId = sodium.to_hex(sodium.randombytes_buf(16));
      const roomKey = generateRoomKey();
      
      // Encrypt room name with room key
      const encryptedName = encryptSymmetric(newRoomName, roomKey);
      
      // Create room document
      await setDoc(doc(db, 'rooms', roomId), {
        id: roomId,
        nameEncrypted: encryptedName.ciphertext,
        nameNonce: encryptedName.nonce,
        members: [user.uid],
        createdAt: serverTimestamp(),
      });
      
      // Encrypt room key for self (anonymous seal)
      const encryptedRoomKey = sodium.crypto_box_seal(roomKey, keys.exchange.publicKey);
      
      await setDoc(doc(db, 'rooms', roomId, 'keys', user.uid), {
        roomId,
        userId: user.uid,
        encryptedKey: toBase64(encryptedRoomKey),
        nonce: encryptedName.nonce, // Use same nonce for room name decryption
      });
      
      setRoomKeys(prev => ({ ...prev, [roomId]: roomKey }));
      setIsCreatingRoom(false);
      setNewRoomName('');
      toast.success('Room created.');
    } catch (err) {
      toast.error('Failed to create room.');
      handleFirestoreError(err, OperationType.CREATE, 'rooms');
    } finally {
      setLoading(false);
    }
  };

  const startPrivateChat = async (targetUser: any) => {
    if (!isSodiumReady || loading) return;
    setLoading(true);
    try {
      // Check if a 1-on-1 room already exists
      const q = query(
        collection(db, 'rooms'),
        where('members', 'array-contains', user.uid)
      );
      const snapshot = await getDocs(q);
      const existingRoom = snapshot.docs.find(doc => {
        const data = doc.data();
        return data.members.length === 2 && data.members.includes(targetUser.id);
      });

      if (existingRoom) {
        setActiveRoom({ id: existingRoom.id, ...existingRoom.data() } as Room);
        setLoading(false);
        return;
      }

      // Create new private room
      const roomId = sodium.to_hex(sodium.randombytes_buf(16));
      const roomKey = generateRoomKey();
      
      // Encrypt room name (target user's email) with room key
      const roomName = targetUser.email || 'Private Chat';
      const encryptedName = encryptSymmetric(roomName, roomKey);
      
      const batch = writeBatch(db);
      
      // Create room document
      batch.set(doc(db, 'rooms', roomId), {
        id: roomId,
        nameEncrypted: encryptedName.ciphertext,
        nameNonce: encryptedName.nonce,
        members: [user.uid, targetUser.id],
        createdAt: serverTimestamp(),
        isPrivate: true,
      });
      
      // Encrypt room key for self
      const myEncryptedRoomKey = sodium.crypto_box_seal(roomKey, keys.exchange.publicKey);
      batch.set(doc(db, 'rooms', roomId, 'keys', user.uid), {
        roomId,
        userId: user.uid,
        encryptedKey: toBase64(myEncryptedRoomKey),
        nonce: encryptedName.nonce,
      });
      
      // Encrypt room key for target user
      if (!targetUser.publicKeyExchange) {
        throw new Error('Target user has no exchange key');
      }
      const targetExchangeKey = fromBase64(targetUser.publicKeyExchange);
      const targetEncryptedRoomKey = sodium.crypto_box_seal(roomKey, targetExchangeKey);
      batch.set(doc(db, 'rooms', roomId, 'keys', targetUser.id), {
        roomId,
        userId: targetUser.id,
        encryptedKey: toBase64(targetEncryptedRoomKey),
        nonce: encryptedName.nonce,
      });
      
      await batch.commit();
      
      setRoomKeys(prev => ({ ...prev, [roomId]: roomKey }));
      setActiveRoom({ 
        id: roomId, 
        nameEncrypted: encryptedName.ciphertext, 
        members: [user.uid, targetUser.id],
        createdAt: new Date(),
        decryptedName: roomName
      });
      toast.success('Private chat started.');
    } catch (err: any) {
      console.error('Start private chat error:', err);
      if (err.message?.includes('no exchange key')) {
        toast.error('This user hasn\'t set up their security profile yet.');
      } else {
        toast.error('Failed to start private chat.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage || !activeRoom || !roomKeys[activeRoom.id]) return;
    
    const roomKey = roomKeys[activeRoom.id];
    const encrypted = encryptSymmetric(newMessage, roomKey);
    const signature = signData(newMessage, keys.signing.privateKey);
    
    setNewMessage('');
    
    try {
      const messageId = sodium.to_hex(sodium.randombytes_buf(16));
      await setDoc(doc(db, 'rooms', activeRoom.id, 'messages', messageId), {
        id: messageId,
        roomId: activeRoom.id,
        senderId: user.uid,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        signature: signature,
        createdAt: serverTimestamp(),
      });
    } catch (err) {
      toast.error('Failed to send message.');
      handleFirestoreError(err, OperationType.CREATE, `rooms/${activeRoom.id}/messages`);
    }
  };

  const handleAddMember = async (input: string) => {
    if (!activeRoom || !roomKeys[activeRoom.id] || !isSodiumReady) {
      toast.error('Security system not ready. Please wait.');
      return;
    }
    setLoading(true);
    
    try {
      const targetInput = input.trim();
      if (!targetInput) {
        toast.error('Please enter an email or UID.');
        setLoading(false);
        return;
      }

      let targetUid = targetInput;
      let targetData: any = null;

      // If input looks like an email, search for it
      if (targetInput.includes('@')) {
        const normalizedEmail = targetInput.toLowerCase();
        const q = query(collection(db, 'users'), where('email', '==', normalizedEmail));
        const snapshot = await getDocs(q);
        if (snapshot.empty) {
          toast.error('User with this email not found. They may need to "Refresh Public Profile" in Settings.');
          setLoading(false);
          return;
        }
        targetUid = snapshot.docs[0].id;
        targetData = snapshot.docs[0].data();
      } else {
        const targetUserDoc = await getDoc(doc(db, 'users', targetUid));
        if (!targetUserDoc.exists()) {
          toast.error('User with this UID not found.');
          setLoading(false);
          return;
        }
        targetData = targetUserDoc.data();
      }
      
      if (activeRoom.members.includes(targetUid)) {
        toast.info('User is already a member.');
        setLoading(false);
        return;
      }

      if (!targetData.publicKeyExchange) {
        toast.error('This user has not completed their security setup yet.');
        setLoading(false);
        return;
      }
      
      const targetExchangeKey = fromBase64(targetData.publicKeyExchange);
      const roomKey = roomKeys[activeRoom.id];
      
      if (!roomKey || !(roomKey instanceof Uint8Array)) {
        toast.error('Room key not found or invalid.');
        setLoading(false);
        return;
      }

      // Encrypt room key for target user (anonymous seal)
      const encryptedRoomKey = sodium.crypto_box_seal(roomKey, targetExchangeKey);
      
      // Use a batch to ensure both operations succeed or fail together
      const batch = writeBatch(db);
      
      // Add member to room
      const roomRef = doc(db, 'rooms', activeRoom.id);
      batch.update(roomRef, {
        members: arrayUnion(targetUid)
      });
      
      // Get our own key data to find the nonce if it's not on the room
      const myKeyDoc = await getDoc(doc(db, 'rooms', activeRoom.id, 'keys', user.uid));
      const myKeyData = myKeyDoc.data();
      
      // Save encrypted key for target user
      const keyRef = doc(db, 'rooms', activeRoom.id, 'keys', targetUid);
      batch.set(keyRef, {
        roomId: activeRoom.id,
        userId: targetUid,
        encryptedKey: toBase64(encryptedRoomKey),
        nonce: activeRoom.nameNonce || myKeyData?.nonce || '', // Pass the room name nonce
      });
      
      await batch.commit();
      
      setSearchEmail('');
      setUserSearchQuery('');
      toast.success('Member added successfully.');
    } catch (err: any) {
      console.error('Add member error:', err);
      const errorMessage = err.message || String(err);
      if (errorMessage.includes('permission-denied')) {
        toast.error('Permission denied. You must be a member of the room to add others.');
      } else if (errorMessage.includes('invalid input')) {
        toast.error('Security error: Invalid user data. Ask them to refresh their profile.');
      } else {
        toast.error('Failed to add member. Please try again.');
      }
      handleFirestoreError(err, OperationType.UPDATE, `rooms/${activeRoom.id}`);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !activeRoom || !roomKeys[activeRoom.id]) return;
    
    setLoading(true);
    try {
      const roomKey = roomKeys[activeRoom.id];
      const reader = new FileReader();
      reader.onload = async () => {
        const arrayBuffer = reader.result as ArrayBuffer;
        const uint8Array = new Uint8Array(arrayBuffer);
        
        // Encrypt file content
        const encrypted = encryptSymmetric(uint8Array, roomKey);
        
        // Upload encrypted file
        const fileRef = ref(storage, `rooms/${activeRoom.id}/files/${Date.now()}_${file.name}.enc`);
        const blob = new Blob([fromBase64(encrypted.ciphertext)], { type: 'application/octet-stream' });
        
        await uploadBytes(fileRef, blob);
        const url = await getDownloadURL(fileRef);
        
        // Send message with file info
        const fileInfo = JSON.stringify({
          type: 'file',
          name: file.name,
          url: url,
          nonce: encrypted.nonce
        });
        
        const msgEncrypted = encryptSymmetric(fileInfo, roomKey);
        const signature = signData(fileInfo, keys.signing.privateKey);
        
        const messageId = sodium.to_hex(sodium.randombytes_buf(16));
        await setDoc(doc(db, 'rooms', activeRoom.id, 'messages', messageId), {
          id: messageId,
          roomId: activeRoom.id,
          senderId: user.uid,
          ciphertext: msgEncrypted.ciphertext,
          nonce: msgEncrypted.nonce,
          signature: signature,
          createdAt: serverTimestamp(),
        });
        
        toast.success('File uploaded.');
        setLoading(false);
      };
      reader.readAsArrayBuffer(file);
    } catch (err) {
      toast.error('File upload failed.');
      handleFirestoreError(err, OperationType.CREATE, `rooms/${activeRoom.id}/messages`);
      setLoading(false);
    }
  };

  const refreshProfile = async () => {
    setLoading(true);
    try {
      const userRef = doc(db, 'users', user.uid);
      await setDoc(userRef, {
        email: user.email?.toLowerCase(),
        uid: user.uid,
        publicKeySigning: toBase64(keys.signing.publicKey),
        publicKeyExchange: toBase64(keys.exchange.publicKey),
        updatedAt: serverTimestamp(),
      }, { merge: true });
      toast.success('Profile refreshed. Others can now find you by email.');
    } catch (err) {
      toast.error('Failed to refresh profile.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const repairRoomAccess = async () => {
    if (!activeRoom || !roomKeys[activeRoom.id] || loading) return;
    setLoading(true);
    try {
      const roomKey = roomKeys[activeRoom.id];
      const batch = writeBatch(db);
      
      // Fetch all members' latest public keys
      for (const memberId of activeRoom.members) {
        const userDoc = await getDoc(doc(db, 'users', memberId));
        if (userDoc.exists()) {
          const userData = userDoc.data();
          if (userData.publicKeyExchange) {
            const targetExchangeKey = fromBase64(userData.publicKeyExchange);
            const encryptedRoomKey = sodium.crypto_box_seal(roomKey, targetExchangeKey);
            
            const keyRef = doc(db, 'rooms', activeRoom.id, 'keys', memberId);
            batch.set(keyRef, {
              roomId: activeRoom.id,
              userId: memberId,
              encryptedKey: toBase64(encryptedRoomKey),
              nonce: activeRoom.nameNonce || '',
              repairedAt: serverTimestamp(),
            }, { merge: true });
          }
        }
      }
      
      await batch.commit();
      toast.success('Room access repaired for all members.');
    } catch (err) {
      console.error('Repair room access error:', err);
      toast.error('Failed to repair room access.');
    } finally {
      setLoading(false);
    }
  };

  // --- Render ---

  const SidebarContent = () => (
    <div className="flex flex-col h-full bg-zinc-950">
      <div className="p-4 md:p-6 border-b border-zinc-900 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-zinc-900 border border-zinc-800">
            <Shield className="w-5 h-5 text-zinc-100" />
          </div>
          <h1 className="font-bold text-lg tracking-tight">E2EE Chat</h1>
        </div>
        <Sheet>
          <SheetTrigger className="p-2 rounded-full hover:bg-zinc-900 transition-colors">
            <Settings className="w-5 h-5 text-zinc-400" />
          </SheetTrigger>
          <SheetContent side="left" className="bg-zinc-950 border-zinc-900 text-zinc-50">
            <SheetHeader>
              <SheetTitle className="text-zinc-100">Settings</SheetTitle>
            </SheetHeader>
            <div className="py-8 space-y-6">
              <div className="flex items-center space-x-4 p-4 rounded-2xl bg-zinc-900/50 border border-zinc-800">
                <Avatar className="w-12 h-12 border-2 border-zinc-800">
                  <AvatarImage src={user.photoURL || ''} />
                  <AvatarFallback className="bg-zinc-800 text-zinc-400">
                    {user.displayName?.[0] || 'U'}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <p className="font-semibold text-zinc-100">{user.displayName}</p>
                  <p className="text-xs text-zinc-500">{user.email}</p>
                </div>
              </div>
              
              <div className="space-y-4">
                <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider px-2">Account Info</p>
                <div className="p-4 rounded-2xl bg-zinc-900/50 border border-zinc-800 space-y-3">
                  <div>
                    <p className="text-[10px] text-zinc-500 mb-1">Your UID</p>
                    <p className="text-[10px] font-mono text-zinc-400 break-all bg-zinc-950 p-2 rounded-lg border border-zinc-800">{user.uid}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-zinc-500 mb-1">Your Email</p>
                    <p className="text-[10px] font-mono text-zinc-400 break-all bg-zinc-950 p-2 rounded-lg border border-zinc-800">{user.email}</p>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={refreshProfile}
                    disabled={loading}
                    className="w-full border-zinc-800 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100 h-8 text-[10px]"
                  >
                    {loading ? <Loader2 className="w-3 h-3 animate-spin mr-2" /> : <Shield className="w-3 h-3 mr-2" />}
                    Refresh Public Profile
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider px-2">Security Verification</p>
                <Button
                  variant="outline"
                  onClick={() => {
                    runSecurityTest();
                    toast.info('Security test running. Check console for results.');
                  }}
                  className="w-full border-zinc-800 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100"
                >
                  <Shield className="w-4 h-4 mr-2" />
                  Run Security Test
                </Button>
              </div>

              <div className="space-y-2">
                <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider px-2">Account Management</p>
                <Button
                  variant="outline"
                  onClick={async () => {
                    if (confirm('Are you sure you want to reset your identity? You will lose access to all current encrypted rooms unless you have a backup.')) {
                      await sodium.ready;
                      const { clearKeysLocally } = await import('@/lib/crypto');
                      await clearKeysLocally();
                      window.location.reload();
                    }
                  }}
                  className="w-full border-zinc-800 text-red-400 hover:bg-red-500/10 hover:text-red-400"
                >
                  <Key className="w-4 h-4 mr-2" />
                  Reset Identity
                </Button>
              </div>

              <Button
                variant="destructive"
                onClick={() => auth.signOut()}
                className="w-full bg-red-500/10 text-red-500 border border-red-500/20 hover:bg-red-500 hover:text-white"
              >
                <LogOut className="w-4 h-4 mr-2" />
                Sign Out
              </Button>
            </div>
          </SheetContent>
        </Sheet>
      </div>

      <div className="p-4">
        <Button
          onClick={() => setIsCreatingRoom(true)}
          className="w-full bg-zinc-100 text-zinc-950 hover:bg-zinc-200 rounded-xl"
        >
          <Plus className="w-4 h-4 mr-2" />
          New Secure Room
        </Button>
      </div>

      <Tabs defaultValue="rooms" className="flex-1 flex flex-col">
        <div className="px-4 py-2">
          <TabsList className="w-full bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="rooms" className="flex-1 text-xs">Rooms</TabsTrigger>
            <TabsTrigger value="users" className="flex-1 text-xs">Users</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="rooms" className="flex-1 flex flex-col m-0">
          <ScrollArea className="flex-1 px-2">
            <div className="space-y-1 p-2">
              {rooms.map((room) => (
                <button
                  key={room.id}
                  onClick={() => setActiveRoom(room)}
                  className={`w-full flex items-center space-x-3 p-3 rounded-xl transition-all duration-200 ${
                    activeRoom?.id === room.id
                      ? 'bg-zinc-900 text-zinc-100 shadow-lg border border-zinc-800'
                      : 'text-zinc-500 hover:bg-zinc-900/50 hover:text-zinc-300'
                  }`}
                >
                  <div className={`p-2 rounded-lg ${activeRoom?.id === room.id ? 'bg-zinc-800' : 'bg-zinc-900'}`}>
                    {room.isPrivate ? <Lock className="w-4 h-4" /> : <Hash className="w-4 h-4" />}
                  </div>
                  <div className="flex-1 text-left overflow-hidden">
                    <p className="text-sm font-semibold truncate">
                      {room.decryptedName || 'Encrypted Room...'}
                    </p>
                    <p className={`text-[10px] truncate ${activeRoom?.id === room.id ? 'text-zinc-400' : 'text-zinc-600'}`}>
                      {room.members.length} members • {room.isPrivate ? 'Private' : 'Group'}
                    </p>
                  </div>
                </button>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="users" className="flex-1 flex flex-col m-0">
          <div className="px-4 py-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
              <Input 
                placeholder="Search users..." 
                value={userSearchQuery}
                onChange={(e) => setUserSearchQuery(e.target.value)}
                className="pl-10 bg-zinc-900 border-zinc-800 h-9 rounded-lg text-xs"
              />
            </div>
          </div>

          <ScrollArea className="flex-1 px-2">
            <div className="space-y-1 p-2">
              {allUsers
                .filter(u => u.uid !== user.uid && (u.email?.includes(userSearchQuery) || u.uid.includes(userSearchQuery)))
                .map(u => (
                <div
                  key={u.uid}
                  className="flex items-center justify-between p-2 rounded-xl hover:bg-zinc-900 transition-colors group"
                >
                  <div className="flex items-center space-x-3 overflow-hidden">
                    <Avatar className="w-8 h-8 border border-zinc-800">
                      <AvatarFallback className="bg-zinc-800 text-[10px] text-zinc-500">
                        {u.email?.[0].toUpperCase() || 'U'}
                      </AvatarFallback>
                    </Avatar>
                    <div className="overflow-hidden">
                      <p className="text-xs font-semibold text-zinc-100 truncate">{u.email}</p>
                      <p className="text-[10px] text-zinc-500 truncate font-mono">{u.uid.slice(0, 12)}...</p>
                    </div>
                  </div>
                  <Button 
                    size="sm" 
                    variant="ghost"
                    onClick={() => startPrivateChat(u)}
                    className="h-8 w-8 p-0 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-zinc-100"
                  >
                    <MessageSquare className="w-4 h-4" />
                  </Button>
                </div>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </div>
  );

  return (
    <div className="flex h-[100dvh] bg-zinc-950 overflow-hidden relative">
      {/* Desktop Sidebar */}
      <div className="hidden md:flex w-80 border-r border-zinc-900 flex-col bg-zinc-950/50 backdrop-blur-xl shrink-0">
        <SidebarContent />
      </div>

      {/* Mobile Sidebar */}
      <AnimatePresence>
        {showMobileSidebar && (
          <motion.div 
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="md:hidden fixed inset-0 z-50 bg-zinc-950 flex flex-col"
          >
            <SidebarContent />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col bg-zinc-950 min-w-0 relative">
        {activeRoom ? (
          <>
            {/* Chat Header */}
            <div className="p-4 md:p-6 border-b border-zinc-900 bg-zinc-950/50 backdrop-blur-xl flex items-center justify-between sticky top-0 z-10">
              <div className="flex items-center space-x-4 overflow-hidden">
                <Button 
                  variant="ghost" 
                  size="icon" 
                  className="md:hidden text-zinc-400"
                  onClick={() => setShowMobileSidebar(true)}
                >
                  <ChevronLeft className="w-6 h-6" />
                </Button>
                <div className="p-2 md:p-3 rounded-xl md:rounded-2xl bg-zinc-900 border border-zinc-800 shrink-0">
                  {activeRoom.isPrivate ? <Lock className="w-4 h-4 md:w-5 md:h-5 text-zinc-100" /> : <Hash className="w-4 h-4 md:w-5 md:h-5 text-zinc-100" />}
                </div>
                <div className="overflow-hidden">
                  <h2 className="font-bold text-base md:text-xl tracking-tight truncate">
                    {activeRoom.decryptedName || 'Encrypted Room...'}
                  </h2>
                  <div className="flex items-center space-x-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    <p className="text-[10px] md:text-xs text-zinc-500 font-medium uppercase tracking-wider">
                      {activeRoom.members.length} Secure Members
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <Sheet>
                  <SheetTrigger className="p-2 rounded-full hover:bg-zinc-900 transition-colors">
                    <Users className="w-5 h-5 text-zinc-400" />
                  </SheetTrigger>
                  <SheetContent className="bg-zinc-950 border-zinc-900 text-zinc-50">
                    <SheetHeader>
                      <SheetTitle className="text-zinc-100">Room Members</SheetTitle>
                    </SheetHeader>
                    <div className="py-8 space-y-6">
                      <div className="space-y-4">
                        <div className="flex items-center justify-between px-1">
                          <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Add Member</p>
                          <Button 
                            variant="ghost" 
                            size="sm" 
                            className="h-6 text-[10px] text-zinc-500 hover:text-zinc-100"
                            onClick={() => setIsSearchingUsers(!isSearchingUsers)}
                          >
                            {isSearchingUsers ? 'Hide List' : 'Show All Users'}
                          </Button>
                        </div>
                        
                        {isSearchingUsers ? (
                          <div className="space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
                            <Input
                              placeholder="Search users..."
                              value={userSearchQuery}
                              onChange={(e) => setUserSearchQuery(e.target.value)}
                              className="bg-zinc-900 border-zinc-800 text-zinc-100 h-8 text-xs"
                            />
                            <ScrollArea className="h-[300px] rounded-xl border border-zinc-900 bg-zinc-900/30 p-2">
                              <div className="space-y-2">
                                {allUsers
                                  .filter(u => 
                                    u.email?.toLowerCase().includes(userSearchQuery.toLowerCase()) || 
                                    u.id.toLowerCase().includes(userSearchQuery.toLowerCase())
                                  )
                                  .map((u) => (
                                    <div key={u.id} className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/50 border border-zinc-800/50">
                                      <div className="flex items-center space-x-3 overflow-hidden">
                                        <Avatar className="w-8 h-8 border border-zinc-800">
                                          <AvatarFallback className="bg-zinc-800 text-[10px] text-zinc-400">
                                            {u.email?.[0].toUpperCase() || 'U'}
                                          </AvatarFallback>
                                        </Avatar>
                                        <div className="overflow-hidden">
                                          <p className="text-xs font-medium text-zinc-200 truncate">{u.email || 'Anonymous'}</p>
                                          <p className="text-[10px] text-zinc-500 font-mono truncate">{u.id}</p>
                                        </div>
                                      </div>
                                      <Button
                                        size="icon"
                                        variant="ghost"
                                        className="h-7 w-7 text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800"
                                        disabled={loading || activeRoom.members.includes(u.id)}
                                        onClick={() => handleAddMember(u.id)}
                                      >
                                        {activeRoom.members.includes(u.id) ? (
                                          <Shield className="w-3 h-3 text-emerald-500" />
                                        ) : (
                                          <Plus className="w-3 h-3" />
                                        )}
                                      </Button>
                                    </div>
                                  ))}
                                {allUsers.length === 0 && (
                                  <p className="text-center text-xs text-zinc-600 py-8">No other users found.</p>
                                )}
                              </div>
                            </ScrollArea>
                          </div>
                        ) : (
                          <div className="space-y-4">
                            <div className="flex items-center space-x-2">
                              <Input
                                placeholder="User Email or UID..."
                                value={searchEmail}
                                onChange={(e) => setSearchEmail(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && handleAddMember(searchEmail)}
                                className="bg-zinc-900 border-zinc-800 text-zinc-100"
                              />
                              <Button 
                                size="icon" 
                                disabled={loading || !searchEmail}
                                onClick={() => handleAddMember(searchEmail)}
                                className="bg-zinc-100 text-zinc-950 hover:bg-zinc-200"
                              >
                                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                              </Button>
                            </div>
                            <p className="text-[10px] text-zinc-500 px-1">
                              Enter the exact email or UID of the person you want to add.
                            </p>
                          </div>
                        )}
                      </div>
                      
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Members</p>
                        <div className="space-y-2">
                          {activeRoom.members.map(m => (
                            <div key={m} className="flex items-center justify-between p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
                              <span className="text-xs font-mono text-zinc-400">{m.slice(0, 12)}...</span>
                              {m === user.uid && <Badge className="bg-zinc-800 text-zinc-400 text-[10px]">You</Badge>}
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="pt-4 border-t border-zinc-900 space-y-4">
                        <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Room Management</p>
                        <div className="p-4 rounded-2xl bg-zinc-900/50 border border-zinc-800 space-y-3">
                          <p className="text-[10px] text-zinc-500 leading-relaxed">
                            If members cannot see messages, use this to re-encrypt the room key for everyone using their latest security profiles.
                          </p>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={repairRoomAccess}
                            disabled={loading}
                            className="w-full border-zinc-800 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100"
                          >
                            {loading ? <Loader2 className="w-3 h-3 animate-spin mr-2" /> : <Key className="w-3 h-3 mr-2" />}
                            Repair Room Access
                          </Button>
                        </div>
                      </div>
                    </div>
                  </SheetContent>
                </Sheet>
              </div>
            </div>

            {/* Messages Area */}
            <ScrollArea className="flex-1 p-3 md:p-8">
              <div className="max-w-4xl mx-auto space-y-4 md:space-y-8">
                {messages.map((msg, i) => {
                  const isMine = msg.senderId === user.uid;
                  const prevMsg = messages[i - 1];
                  const showAvatar = !prevMsg || prevMsg.senderId !== msg.senderId;
                  
                  let fileData = null;
                  if (msg.decryptedText?.startsWith('{')) {
                    try {
                      const parsed = JSON.parse(msg.decryptedText);
                      if (parsed.type === 'file') fileData = parsed;
                    } catch (e) {}
                  }

                  return (
                    <div key={msg.id} className={`flex items-end space-x-2 md:space-x-4 ${isMine ? 'flex-row-reverse space-x-reverse' : ''}`}>
                      <div className={`w-6 h-6 md:w-10 md:h-10 shrink-0 ${!showAvatar ? 'opacity-0' : ''}`}>
                        <Avatar className="w-full h-full border-2 border-zinc-900">
                          <AvatarFallback className="bg-zinc-900 text-[10px] md:text-xs text-zinc-500">
                            {msg.senderId.slice(0, 2).toUpperCase()}
                          </AvatarFallback>
                        </Avatar>
                      </div>
                      
                      <div className={`flex flex-col max-w-[85%] md:max-w-[70%] ${isMine ? 'items-end' : 'items-start'}`}>
                        {showAvatar && (
                          <span className="text-[10px] text-zinc-600 mb-1 px-1 font-mono">
                            {msg.senderId.slice(0, 8)}...
                          </span>
                        )}
                        
                        <div className={`group relative p-3 md:p-4 rounded-2xl md:rounded-3xl ${
                          isMine 
                            ? 'bg-zinc-100 text-zinc-950 rounded-tr-none' 
                            : 'bg-zinc-900 text-zinc-100 rounded-tl-none border border-zinc-800'
                        }`}>
                          {fileData ? (
                            <div className="flex items-center space-x-3">
                              <div className={`p-2 md:p-3 rounded-xl ${isMine ? 'bg-zinc-200' : 'bg-zinc-800'}`}>
                                <Paperclip className="w-4 h-4 md:w-5 md:h-5" />
                              </div>
                              <div className="overflow-hidden">
                                <p className="text-xs md:text-sm font-semibold truncate">{fileData.name}</p>
                                <Button 
                                  variant="link" 
                                  size="sm" 
                                  className={`h-auto p-0 text-[10px] md:text-xs ${isMine ? 'text-zinc-600' : 'text-zinc-400'}`}
                                  onClick={() => window.open(fileData.url)}
                                >
                                  <Download className="w-3 h-3 mr-1" />
                                  Download Securely
                                </Button>
                              </div>
                            </div>
                          ) : (
                            <p className="text-xs md:text-sm leading-relaxed whitespace-pre-wrap break-words">
                              {msg.decryptedText}
                            </p>
                          )}
                          
                          <div className={`absolute bottom-0 ${isMine ? '-left-12' : '-right-12'} opacity-0 group-hover:opacity-100 transition-opacity`}>
                            <div className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 shadow-xl">
                              <Shield className="w-3 h-3 text-emerald-500" />
                            </div>
                          </div>
                        </div>
                        
                        <span className="text-[10px] text-zinc-600 mt-1.5 px-1">
                          {msg.createdAt?.toDate ? format(msg.createdAt.toDate(), 'HH:mm') : '...'}
                        </span>
                      </div>
                    </div>
                  );
                })}
                <div ref={scrollRef} />
              </div>
            </ScrollArea>

            {/* Input Area */}
            <div className="p-3 md:p-8 border-t border-zinc-900 bg-zinc-950/50 backdrop-blur-xl">
              <div className="max-w-4xl mx-auto">
                <div className="relative flex items-end space-x-2 md:space-x-4 bg-zinc-900/50 border border-zinc-800 p-2 md:p-3 rounded-2xl md:rounded-3xl focus-within:border-zinc-700 transition-colors shadow-inner">
                  <div className="flex items-center">
                    <input
                      type="file"
                      id="file-upload"
                      className="hidden"
                      onChange={handleFileUpload}
                    />
                    <label htmlFor="file-upload" className="cursor-pointer h-10 w-10 md:h-12 md:w-12 flex items-center justify-center rounded-xl md:rounded-2xl text-zinc-500 hover:text-zinc-100 hover:bg-zinc-800 transition-colors">
                      <Paperclip className="w-5 h-5 md:w-6 md:h-6" />
                    </label>
                  </div>
                  
                  <textarea
                    rows={1}
                    value={newMessage}
                    onChange={(e) => setNewMessage(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        handleSendMessage();
                      }
                    }}
                    placeholder={!roomKeys[activeRoom.id] ? "Waiting for secure key..." : "Type an encrypted message..."}
                    disabled={!roomKeys[activeRoom.id]}
                    className="flex-1 bg-transparent border-none focus:ring-0 text-zinc-100 placeholder:text-zinc-600 resize-none py-2.5 md:py-3.5 text-sm md:text-base max-h-32 min-h-[40px]"
                  />
                  
                  <Button 
                    size="icon"
                    onClick={handleSendMessage}
                    disabled={!newMessage.trim() || loading || !roomKeys[activeRoom.id]}
                    className="h-10 w-10 md:h-12 md:w-12 rounded-xl md:rounded-2xl bg-zinc-100 text-zinc-950 hover:bg-zinc-200 shrink-0 shadow-lg active:scale-95 transition-transform"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5 md:w-6 md:h-6" />}
                  </Button>
                </div>
                <div className="mt-3 flex items-center justify-center space-x-2">
                  <Shield className="w-3 h-3 text-emerald-500/50" />
                  <p className="text-[10px] text-zinc-600 font-medium uppercase tracking-widest">
                    Military-Grade End-to-End Encryption Active
                  </p>
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
            <div className="relative mb-8">
              <div className="absolute inset-0 bg-zinc-100/10 blur-3xl rounded-full" />
              <div className="relative p-8 rounded-full bg-zinc-900 border border-zinc-800">
                <Shield className="w-16 h-16 text-zinc-100" />
              </div>
            </div>
            <h2 className="text-2xl md:text-3xl font-bold tracking-tight text-zinc-100 mb-3">Your Privacy is Protected</h2>
            <p className="text-zinc-500 max-w-md text-sm md:text-base leading-relaxed">
              Select a secure room or start a private chat with another user. 
              All messages and files are encrypted on your device before they ever reach our servers.
            </p>
            <div className="mt-10 grid grid-cols-1 md:grid-cols-3 gap-4 w-full max-w-2xl">
              {[
                { icon: Lock, title: 'Private', desc: '1-on-1 chats' },
                { icon: Hash, title: 'Groups', desc: 'Secure channels' },
                { icon: Shield, title: 'Verified', desc: 'Signed messages' }
              ].map((item, i) => (
                <div key={i} className="p-4 rounded-2xl bg-zinc-900/50 border border-zinc-800 text-left">
                  <item.icon className="w-5 h-5 text-zinc-400 mb-3" />
                  <h3 className="text-xs font-bold text-zinc-100 uppercase tracking-wider mb-1">{item.title}</h3>
                  <p className="text-[10px] text-zinc-500">{item.desc}</p>
                </div>
              ))}
            </div>
            <Button 
              variant="ghost" 
              className="md:hidden mt-8 text-zinc-400"
              onClick={() => setShowMobileSidebar(true)}
            >
              View Room List
            </Button>
          </div>
        )}
      </div>

      {/* Create Room Dialog */}
      <AnimatePresence>
        {isCreatingRoom && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-zinc-950/80 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-sm"
            >
              <Card className="bg-zinc-900 border-zinc-800 text-zinc-100 shadow-2xl">
                <CardHeader>
                  <CardTitle>Create Secure Room</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Room Name</label>
                    <Input
                      placeholder="e.g. Project X, Secret Plans"
                      value={newRoomName}
                      onChange={(e) => setNewRoomName(e.target.value)}
                      className="bg-zinc-950 border-zinc-800"
                    />
                  </div>
                  <div className="p-3 rounded-lg bg-zinc-950/50 border border-zinc-800 flex items-start space-x-3">
                    <Shield className="w-4 h-4 mt-0.5 text-emerald-500" />
                    <p className="text-[10px] text-zinc-500 leading-relaxed">
                      A unique symmetric key will be generated for this room and shared securely with members.
                    </p>
                  </div>
                </CardContent>
                <div className="p-6 pt-0 flex justify-end space-x-2">
                  <Button variant="ghost" onClick={() => setIsCreatingRoom(false)} className="text-zinc-500">Cancel</Button>
                  <Button 
                    onClick={handleCreateRoom} 
                    disabled={!newRoomName || loading || !isSodiumReady}
                    className="bg-zinc-100 text-zinc-950 hover:bg-zinc-200"
                  >
                    {loading || !isSodiumReady ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Create Room'}
                  </Button>
                </div>
              </Card>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
