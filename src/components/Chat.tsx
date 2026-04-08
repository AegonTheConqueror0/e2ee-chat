import React, { useState, useEffect, useRef } from 'react';
import { User as FirebaseUser } from 'firebase/auth';
import { IdentityKeys, encryptSymmetric, decryptSymmetric, decryptSymmetricBytes, generateRoomKey, signData, verifySignature, encryptAsymmetric, decryptAsymmetric, hashRoomPin, verifyRoomPin, encryptRoomKeyWithPin, decryptRoomKeyWithPin, toBase64, fromBase64 } from '@/lib/crypto';
import { db, collection, query, where, onSnapshot, orderBy, addDoc, serverTimestamp, doc, getDoc, setDoc, getDocs, storage, auth, handleFirestoreError, OperationType, updateDoc, arrayUnion, limit, writeBatch, deleteDoc } from '@/firebase';
import { ref, uploadBytes, getDownloadURL, listAll, deleteObject } from 'firebase/storage';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet';
import { MessageSquare, Plus, Send, Shield, Users, Settings, LogOut, Paperclip, Loader2, Search, Key, Download, ChevronLeft, Hash, Lock, UserPlus, Trash2, MapPin, Image, Video } from 'lucide-react';
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
  pinHash?: string;
  pinSalt?: string;
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
  deliveredTo?: string[];
  seenBy?: string[];
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
  const [newRoomPin, setNewRoomPin] = useState('');
  const [pinError, setPinError] = useState<string | null>(null);
  const [roomPinInput, setRoomPinInput] = useState('');
  const [roomPinVerified, setRoomPinVerified] = useState<Record<string, boolean>>({});
  const [roomPinAttempts, setRoomPinAttempts] = useState<Record<string, number>>({});
  const [isSodiumReady, setIsSodiumReady] = useState(false);
  const [showMobileSidebar, setShowMobileSidebar] = useState(true);
  const MAX_PIN_ATTEMPTS = 3;
  const [userStatusMap, setUserStatusMap] = useState<Record<string, { lastActive: number; status: 'online' | 'away' | 'inactive'; currentRoomId?: string }>>({});
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const messagesScrollAreaRef = useRef<HTMLDivElement>(null);
  const [shouldAutoScroll, setShouldAutoScroll] = useState(false);
  const [isInitialLoad, setIsInitialLoad] = useState(true);
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [showJumpToBottom, setShowJumpToBottom] = useState(false);

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

  // --- User Status Tracking ---
  useEffect(() => {
    const q = query(collection(db, 'users'));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const statusMap: typeof userStatusMap = {};
      snapshot.docs.forEach(doc => {
        const data = doc.data();
        const lastActive = data.lastActive?.toDate?.()?.getTime() || 0;
        const currentRoomId = data.currentRoomId || undefined;
        const now = Date.now();
        const diff = now - lastActive;
        
        let status: 'online' | 'away' | 'inactive';
        if (diff < 2 * 60 * 1000) { // 2 minutes
          status = 'online';
        } else if (diff < 30 * 60 * 1000) { // 30 minutes
          status = 'away';
        } else {
          status = 'inactive';
        }
        
        statusMap[doc.id] = { lastActive, status, currentRoomId };
      });
      setUserStatusMap(statusMap);
    });
    return () => unsubscribe();
  }, []);

  // Update own lastActive timestamp periodically
  useEffect(() => {
    if (!user.uid) return;
    
    const updateLastActive = async () => {
      try {
        await setDoc(doc(db, 'users', user.uid), {
          lastActive: serverTimestamp(),
        }, { merge: true });
      } catch (err) {
        console.error('Failed to update lastActive:', err);
      }
    };
    
    updateLastActive();
    const interval = setInterval(updateLastActive, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, [user.uid]);

  useEffect(() => {
    if (!user.uid) return;

    const updateCurrentRoom = async () => {
      try {
        await setDoc(doc(db, 'users', user.uid), {
          currentRoomId: activeRoom?.id || null,
        }, { merge: true });
      } catch (err) {
        console.error('Failed to update current room status:', err);
      }
    };

    updateCurrentRoom();
  }, [activeRoom?.id, user.uid]);

  useEffect(() => {
    if (!activeRoom) return;
    setRoomPinInput('');
    setPinError(null);
    if (!activeRoom.pinHash) {
      setRoomPinVerified(prev => ({ ...prev, [activeRoom.id]: true }));
    }
  }, [activeRoom?.id, activeRoom?.pinHash]);

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
            
            // Decrypt room name asynchronously to avoid blocking the UI
            if (room.nameEncrypted) {
              const nonce = room.nameNonce || keyData.nonce;
              if (nonce) {
                try {
                  const decryptedName = decryptSymmetric(
                    { ciphertext: room.nameEncrypted, nonce },
                    decryptedKey
                  );
                  setRooms(prev => prev.map(r => r.id === room.id ? { ...r, decryptedName } : r));
                } catch (decryptErr) {
                  console.error('Failed to decrypt room name:', decryptErr);
                }
              }
            }
          } catch (err) {
            console.error('Failed to decrypt room key:', err);
            if (!room.pinHash || !room.pinEncryptedKey || !room.pinEncryptedNonce) {
              toast.error(`Failed to decrypt key for room "${room.id.slice(0, 8)}...". Enter the room PIN to unlock it on this device.`, {
                id: `decrypt-fail-${room.id}`,
              });
            } else {
              console.info(`Room "${room.id}" is PIN protected and will unlock after PIN entry.`);
            }
          }
        }
      }, (err) => {
        handleFirestoreError(err, OperationType.GET, `rooms/${room.id}/keys/${user.uid}`);
      });
    });

    return () => unsubscribes.forEach(unsub => unsub());
  }, [rooms.length, user.uid, keys.exchange.publicKey, keys.exchange.privateKey]);

  // --- Message Subscription ---

  useEffect(() => {
    if (!activeRoom || !roomKeys[activeRoom.id] || (activeRoom.pinHash && !roomPinVerified[activeRoom.id])) {
      setMessages([]);
      return;
    }

    const q = query(
      collection(db, 'rooms', activeRoom.id, 'messages'),
      orderBy('createdAt', 'asc')
    );

    const unsubscribe = onSnapshot(q, async (snapshot) => {
      const batch = writeBatch(db);
      let hasUpdate = false;

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

        if (data.senderId !== user.uid) {
          if (!Array.isArray(data.deliveredTo) || !data.deliveredTo.includes(user.uid)) {
            batch.update(doc.ref, { deliveredTo: arrayUnion(user.uid) });
            hasUpdate = true;
          }
          if (!Array.isArray(data.seenBy) || !data.seenBy.includes(user.uid)) {
            batch.update(doc.ref, { seenBy: arrayUnion(user.uid) });
            hasUpdate = true;
          }
        }

        return {
          ...data,
          id: doc.id,
          decryptedText,
          isMine: data.senderId === user.uid
        };
      });

      setMessages(msgs);

      if (hasUpdate) {
        try {
          await batch.commit();
        } catch (err) {
          console.error('Failed to update delivered/seen metadata:', err);
        }
      }
      
      // Auto-scroll only for initial load or user actions (sending message/file/location)
      setTimeout(() => {
        if (!messagesScrollAreaRef.current) return;
        const viewport = messagesScrollAreaRef.current.querySelector('[data-slot="scroll-area-viewport"]') as HTMLElement;
        if (!viewport) return;

        const isCurrentlyAtBottom = viewport.scrollTop + viewport.clientHeight >= viewport.scrollHeight - 10;

        if (isInitialLoad || shouldAutoScroll || (isAtBottom && isCurrentlyAtBottom)) {
          viewport.scrollTop = viewport.scrollHeight;
          setShowJumpToBottom(false);

          if (isInitialLoad) {
            setIsInitialLoad(false);
          }
          if (shouldAutoScroll) {
            setShouldAutoScroll(false);
          }
        } else if (!isCurrentlyAtBottom) {
          setShowJumpToBottom(true);
        }
      }, 100);
    });

    return () => unsubscribe();
  }, [activeRoom, roomKeys, user.uid, roomPinVerified]);

  // --- Scroll Position Tracking ---

  useEffect(() => {
    if (!messagesScrollAreaRef.current) return;

    const viewport = messagesScrollAreaRef.current.querySelector('[data-slot="scroll-area-viewport"]') as HTMLElement;
    if (!viewport) return;

    const onScroll = () => {
      const isCurrentlyAtBottom = viewport.scrollTop + viewport.clientHeight >= viewport.scrollHeight - 10;
      setIsAtBottom(isCurrentlyAtBottom);
      if (isCurrentlyAtBottom) {
        setShowJumpToBottom(false);
      } else {
        setShowJumpToBottom(true);
        setIsInitialLoad(false);
      }
    };

    viewport.addEventListener('scroll', onScroll, { passive: true });
    onScroll();

    return () => viewport.removeEventListener('scroll', onScroll);
  }, [activeRoom?.id]);

  useEffect(() => {
    if (activeRoom) {
      setShowMobileSidebar(false);
      // Reset scroll state when entering a room - allow initial scroll to bottom
      setIsInitialLoad(true);
      setShowJumpToBottom(false);
    }
  }, [activeRoom?.id]);

  const scrollToBottom = () => {
    if (!messagesScrollAreaRef.current) return;
    const viewport = messagesScrollAreaRef.current.querySelector('[data-slot="scroll-area-viewport"]') as HTMLElement;
    if (!viewport) return;
    viewport.scrollTop = viewport.scrollHeight;
    setShowJumpToBottom(false);
    setIsInitialLoad(false);
    setShouldAutoScroll(false);
    setIsAtBottom(true);
  };

  // --- Actions ---

  const handleCreateRoom = async () => {
    if (!newRoomName || !newRoomPin || !isSodiumReady) {
      setPinError('Room name and 4-digit PIN are required.');
      return;
    }
    if (!/^[0-9]{4}$/.test(newRoomPin)) {
      setPinError('PIN must be exactly 4 digits.');
      return;
    }
    setLoading(true);
    try {
      const roomId = sodium.to_hex(sodium.randombytes_buf(16));
      const roomKey = generateRoomKey();
      const { pinHash, pinSalt } = hashRoomPin(newRoomPin);
      
      // Encrypt room name with room key
      const encryptedName = encryptSymmetric(newRoomName, roomKey);
      
      // Encrypt room key with PIN so it can be restored on any device with the code
      const pinEncryptedKey = await encryptRoomKeyWithPin(roomKey, newRoomPin, pinSalt);
      
      // Use batch to ensure both operations succeed or fail together
      const batch = writeBatch(db);
      
      // Add room document
      batch.set(doc(db, 'rooms', roomId), {
        id: roomId,
        nameEncrypted: encryptedName.ciphertext,
        nameNonce: encryptedName.nonce,
        members: [user.uid],
        createdAt: serverTimestamp(),
        pinHash,
        pinSalt,
        pinEncryptedKey: pinEncryptedKey.ciphertext,
        pinEncryptedNonce: pinEncryptedKey.nonce,
      });
      
      // Add key document for self
      const encryptedRoomKey = sodium.crypto_box_seal(roomKey, keys.exchange.publicKey);
      batch.set(doc(db, 'rooms', roomId, 'keys', user.uid), {
        roomId,
        userId: user.uid,
        encryptedKey: toBase64(encryptedRoomKey),
        nonce: encryptedName.nonce, // Use same nonce for room name decryption
      });
      
      await batch.commit();
      
      setRoomKeys(prev => ({ ...prev, [roomId]: roomKey }));
      setIsCreatingRoom(false);
      setNewRoomName('');
      setNewRoomPin('');
      setPinError(null);
      toast.success('Room created.');
    } catch (err) {
      toast.error('Failed to create room.');
      handleFirestoreError(err, OperationType.CREATE, 'rooms');
    } finally {
      setLoading(false);
    }
  };

  const createPrivateRoom = async (targetUser: any, roomNameOverride?: string, pin?: string) => {
    if (!pin || !/^[0-9]{4}$/.test(pin)) {
      throw new Error('A valid 4-digit PIN is required for private chats.');
    }

    const roomId = sodium.to_hex(sodium.randombytes_buf(16));
    const roomKey = generateRoomKey();
    const { pinHash, pinSalt } = hashRoomPin(pin);
    const roomName = roomNameOverride || targetUser.email || 'Private Chat';
    const encryptedName = encryptSymmetric(roomName, roomKey);
    const pinEncryptedKey = await encryptRoomKeyWithPin(roomKey, pin, pinSalt);

    const batch = writeBatch(db);
    batch.set(doc(db, 'rooms', roomId), {
      id: roomId,
      nameEncrypted: encryptedName.ciphertext,
      nameNonce: encryptedName.nonce,
      members: [user.uid, targetUser.id],
      createdAt: serverTimestamp(),
      isPrivate: true,
      pinHash,
      pinSalt,
      pinEncryptedKey: pinEncryptedKey.ciphertext,
      pinEncryptedNonce: pinEncryptedKey.nonce,
    });

    const myEncryptedRoomKey = sodium.crypto_box_seal(roomKey, keys.exchange.publicKey);
    batch.set(doc(db, 'rooms', roomId, 'keys', user.uid), {
      roomId,
      userId: user.uid,
      encryptedKey: toBase64(myEncryptedRoomKey),
      nonce: encryptedName.nonce,
    });
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
    const newRoom: Room = {
      id: roomId,
      nameEncrypted: encryptedName.ciphertext,
      nameNonce: encryptedName.nonce,
      members: [user.uid, targetUser.id],
      createdAt: new Date(),
      decryptedName: roomName,
      isPrivate: true,
    };

    setRoomKeys(prev => ({ ...prev, [roomId]: roomKey }));
    setRoomPinVerified(prev => ({ ...prev, [roomId]: true }));
    setActiveRoom(newRoom);
    return newRoom;
  };

  const verifyRoomPinForRoom = async (pin: string) => {
    if (!activeRoom) return false;
    if (!activeRoom.pinHash || !activeRoom.pinSalt) {
      setRoomPinVerified(prev => ({ ...prev, [activeRoom.id]: true }));
      return true;
    }

    if (!verifyRoomPin(pin, activeRoom.pinSalt, activeRoom.pinHash)) {
      addRoomPinAttempt(activeRoom.id);
      const remaining = MAX_PIN_ATTEMPTS - ((roomPinAttempts[activeRoom.id] || 0) + 1);
      setPinError(remaining > 0 ? `Wrong PIN. ${remaining} attempt(s) left.` : 'Room locked after 3 failed PIN attempts.');
      return false;
    }

    if (!roomKeys[activeRoom.id]) {
      if (activeRoom.pinEncryptedKey && activeRoom.pinEncryptedNonce) {
        try {
          const decryptedKey = await decryptRoomKeyWithPin(
            { ciphertext: activeRoom.pinEncryptedKey, nonce: activeRoom.pinEncryptedNonce },
            pin,
            activeRoom.pinSalt
          );
          setRoomKeys(prev => ({ ...prev, [activeRoom.id]: decryptedKey }));
        } catch (err) {
          console.error('Failed to decrypt room key with PIN:', err);
          setPinError('Correct PIN, but the room key could not be decrypted. Repair room access.');
          return false;
        }
      } else {
        // Migrate older rooms by using the user's sealed key document and the verified PIN.
        try {
          const keyDoc = await getDoc(doc(db, 'rooms', activeRoom.id, 'keys', user.uid));
          if (!keyDoc.exists()) {
            setPinError('Correct PIN, but no user key document exists for this room. Repair room access.');
            return false;
          }

          const keyData = keyDoc.data();
          const encryptedKey = fromBase64(keyData.encryptedKey);
          const decryptedKey = sodium.crypto_box_seal_open(
            encryptedKey,
            keys.exchange.publicKey,
            keys.exchange.privateKey
          );

          const pinEncryptedKey = await encryptRoomKeyWithPin(decryptedKey, pin, activeRoom.pinSalt);
          await updateDoc(doc(db, 'rooms', activeRoom.id), {
            pinEncryptedKey: pinEncryptedKey.ciphertext,
            pinEncryptedNonce: pinEncryptedKey.nonce,
          });

          setRoomKeys(prev => ({ ...prev, [activeRoom.id]: decryptedKey }));
        } catch (err) {
          console.error('Failed to migrate old room key with PIN:', err);
          setPinError('Correct PIN, but this room cannot be unlocked on this device yet. Repair room access.');
          return false;
        }
      }
    }

    setRoomPinVerified(prev => ({ ...prev, [activeRoom.id]: true }));
    setPinError(null);
    setRoomPinInput('');
    return true;
  };

  const addRoomPinAttempt = (roomId: string) => {
    setRoomPinAttempts(prev => ({
      ...prev,
      [roomId]: (prev[roomId] || 0) + 1,
    }));
  };

  const startPrivateChat = async (targetUser: any) => {
    if (!isSodiumReady || loading) return;
    setLoading(true);
    try {
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
        const roomData = existingRoom.data() as Room;
        const keyDoc = await getDoc(doc(db, 'rooms', existingRoom.id, 'keys', user.uid));
        let canAccessExisting = false;

        if (keyDoc.exists()) {
          try {
            const keyData = keyDoc.data();
            const encryptedKey = fromBase64(keyData.encryptedKey);
            sodium.crypto_box_seal_open(encryptedKey, keys.exchange.publicKey, keys.exchange.privateKey);
            canAccessExisting = true;
          } catch (err) {
            canAccessExisting = false;
          }
        }

        setActiveRoom({ ...roomData, id: existingRoom.id } as Room);
        if (canAccessExisting) {
          setLoading(false);
          return;
        }

        // Existing room may be protected by PIN or old key mismatch.
        toast('Existing chat found. Enter the room PIN to continue.');
        setLoading(false);
        return;
      }

      const newPin = window.prompt('Enter a 4-digit PIN for this private chat:');
      if (!newPin || !/^[0-9]{4}$/.test(newPin)) {
        toast.error('A valid 4-digit PIN is required to start a private chat.');
        setLoading(false);
        return;
      }

      await createPrivateRoom(targetUser, undefined, newPin);
      toast.success('Private chat started. Share the PIN with the other user.');
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
    setShouldAutoScroll(true); // Always scroll when sending a message
    setShowJumpToBottom(false);
    
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
        deliveredTo: [],
        seenBy: [],
      });
    } catch (err) {
      toast.error('Failed to send message.');
      handleFirestoreError(err, OperationType.CREATE, `rooms/${activeRoom.id}/messages`);
    }
  };

  const handleSendLocation = async () => {
    if (!activeRoom || !roomKeys[activeRoom.id] || (activeRoom.pinHash && !roomPinVerified[activeRoom.id])) {
      toast.error('Secure room not ready.');
      return;
    }

    if (!navigator.geolocation) {
      toast.error('Geolocation is not supported in this browser.');
      return;
    }

    setLoading(true);
    setShouldAutoScroll(true); // Always scroll when sending location
    setShowJumpToBottom(false);
    try {
      const position = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          enableHighAccuracy: true,
          maximumAge: 60000,
          timeout: 20000,
        });
      });

      const locationPayload = {
        type: 'location',
        latitude: position.coords.latitude,
        longitude: position.coords.longitude,
        accuracy: position.coords.accuracy,
        label: 'Shared location',
      };

      const roomKey = roomKeys[activeRoom.id];
      const payload = JSON.stringify(locationPayload);
      const encrypted = encryptSymmetric(payload, roomKey);
      const signature = signData(payload, keys.signing.privateKey);

      const messageId = sodium.to_hex(sodium.randombytes_buf(16));
      await setDoc(doc(db, 'rooms', activeRoom.id, 'messages', messageId), {
        id: messageId,
        roomId: activeRoom.id,
        senderId: user.uid,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        signature,
        createdAt: serverTimestamp(),
        deliveredTo: [],
        seenBy: [],
      });
      toast.success('Location shared securely.');
    } catch (err) {
      console.error('Send location error:', err);
      toast.error('Failed to share location.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadEncryptedFile = async (fileData: any) => {
    if (!activeRoom || !roomKeys[activeRoom.id] || (activeRoom.pinHash && !roomPinVerified[activeRoom.id])) {
      toast.error('Secure room not ready.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(fileData.url);
      if (!response.ok) throw new Error('Unable to fetch file.');
      const encryptedArrayBuffer = await response.arrayBuffer();
      const encryptedBytes = new Uint8Array(encryptedArrayBuffer);
      const decryptedBytes = decryptSymmetricBytes({ ciphertext: sodium.to_base64(encryptedBytes), nonce: fileData.nonce }, roomKeys[activeRoom.id]);
      const blob = new Blob([new Uint8Array(decryptedBytes)], { type: fileData.mimeType || 'application/octet-stream' });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = fileData.name || 'download';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
      toast.success('File downloaded securely.');
    } catch (err) {
      console.error('File download error:', err);
      toast.error('Could not download file securely.');
    } finally {
      setLoading(false);
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

  const handleDeleteRoom = async () => {
    if (!activeRoom) return;
    if (!confirm(`Delete ${activeRoom.decryptedName || 'this room'}? This action cannot be undone.`)) {
      return;
    }
    setLoading(true);
    try {
      const roomRef = doc(db, 'rooms', activeRoom.id);
      const [messagesSnapshot, keysSnapshot] = await Promise.all([
        getDocs(collection(db, 'rooms', activeRoom.id, 'messages')),
        getDocs(collection(db, 'rooms', activeRoom.id, 'keys')),
      ]);

      const allDeleteRefs = [
        ...messagesSnapshot.docs.map(docSnap => docSnap.ref),
        ...keysSnapshot.docs.map(docSnap => docSnap.ref),
      ];

      const chunkSize = 500;
      for (let i = 0; i < allDeleteRefs.length; i += chunkSize) {
        const batch = writeBatch(db);
        allDeleteRefs.slice(i, i + chunkSize).forEach(refToDelete => batch.delete(refToDelete));
        await batch.commit();
      }

      await deleteDoc(roomRef);

      try {
        const filesRef = ref(storage, `rooms/${activeRoom.id}/files`);
        const fileList = await listAll(filesRef);
        await Promise.all(fileList.items.map(item => deleteObject(item)));
      } catch (storageError) {
        console.warn('Unable to delete associated room storage files:', storageError);
      }

      setRoomKeys(prev => {
        const updated = { ...prev };
        delete updated[activeRoom.id];
        return updated;
      });
      setRoomPinVerified(prev => {
        const updated = { ...prev };
        delete updated[activeRoom.id];
        return updated;
      });
      setActiveRoom(null);
      setShowMobileSidebar(true);
      toast.success('Room deleted successfully.');
    } catch (err) {
      toast.error('Failed to delete room.');
      console.error('Delete room error:', err);
      handleFirestoreError(err, OperationType.DELETE, `rooms/${activeRoom?.id}`);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !activeRoom || !roomKeys[activeRoom.id] || (activeRoom.pinHash && !roomPinVerified[activeRoom.id])) return;
    if (fileInputRef.current) fileInputRef.current.value = '';
    
    setLoading(true);
    setShouldAutoScroll(true); // Always scroll when uploading file
    setShowJumpToBottom(false);
    try {
      const roomKey = roomKeys[activeRoom.id];
      const reader = new FileReader();
      reader.onload = async () => {
        const arrayBuffer = reader.result as ArrayBuffer;
        const uint8Array = new Uint8Array(arrayBuffer);
        
        // Encrypt file content
        const encrypted = encryptSymmetric(uint8Array, roomKey);
        
        // Upload encrypted file
        const fileId = sodium.to_hex(sodium.randombytes_buf(16));
        const fileRef = ref(storage, `rooms/${activeRoom.id}/files/${fileId}_${file.name}.enc`);
        const blob = new Blob([new Uint8Array(fromBase64(encrypted.ciphertext))], { type: 'application/octet-stream' });
        
        await uploadBytes(fileRef, blob);
        const url = await getDownloadURL(fileRef);
        
        // Send message with file info
        const fileInfo = JSON.stringify({
          type: 'file',
          name: file.name,
          url: url,
          nonce: encrypted.nonce,
          mimeType: file.type,
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
          deliveredTo: [],
          seenBy: [],
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

  const ensureRoomKeysDistributed = async (room: Room, roomKey: Uint8Array) => {
    try {
      const memberDocs = await Promise.all(
        room.members.map(memberId => getDoc(doc(db, 'users', memberId)))
      );

      const batch = writeBatch(db);
      let hasUpdate = false;

      for (let i = 0; i < room.members.length; i += 1) {
        const memberId = room.members[i];
        const userDoc = memberDocs[i];
        if (!userDoc.exists()) continue;

        const userData = userDoc.data();
        if (!userData.publicKeyExchange) continue;

        const targetExchangeKey = fromBase64(userData.publicKeyExchange);
        const encryptedRoomKey = sodium.crypto_box_seal(roomKey, targetExchangeKey);
        const keyRef = doc(db, 'rooms', room.id, 'keys', memberId);

        batch.set(keyRef, {
          roomId: room.id,
          userId: memberId,
          encryptedKey: toBase64(encryptedRoomKey),
          nonce: room.nameNonce || '',
          repairedAt: serverTimestamp(),
        }, { merge: true });

        hasUpdate = true;
      }

      if (hasUpdate) {
        await batch.commit();
      }
    } catch (err) {
      console.error('Automatic room key distribution failed:', err);
    }
  };

  useEffect(() => {
    if (!activeRoom || !roomKeys[activeRoom.id] || loading) return;

    let isCancelled = false;
    const syncKeys = async () => {
      const roomKey = roomKeys[activeRoom.id];
      if (!roomKey) return;

      try {
        await ensureRoomKeysDistributed(activeRoom, roomKey);
      } catch (err) {
        if (!isCancelled) {
          console.error('Error auto repairing room keys:', err);
        }
      }
    };

    syncKeys();
    return () => {
      isCancelled = true;
    };
  }, [activeRoom?.id, roomKeys, loading]);

  // --- Render ---

  const getStatusColor = (status: 'online' | 'away' | 'inactive') => {
    switch (status) {
      case 'online':
        return 'bg-emerald-500';
      case 'away':
        return 'bg-yellow-500';
      case 'inactive':
        return 'bg-zinc-600';
    }
  };

  const getStatusLabel = (status: 'online' | 'away' | 'inactive') => {
    switch (status) {
      case 'online':
        return 'Online';
      case 'away':
        return 'Away';
      case 'inactive':
        return 'Inactive';
    }
  };

  const getMemberPresenceLabel = (memberId: string) => {
    const memberStatus = userStatusMap[memberId];
    if (!memberStatus) {
      return 'Inactive';
    }

    if (memberStatus.currentRoomId === activeRoom?.id) {
      return memberStatus.status === 'online' ? 'In room' : 'Idle in room';
    }

    return getStatusLabel(memberStatus.status);
  };

  const getMessageStatus = (msg: Message) => {
    if (!activeRoom || !msg.isMine) return '';
    const otherMembers = activeRoom.members.filter(id => id !== user.uid);
    if (otherMembers.length === 0) return 'Seen';

    const seenBy = new Set(msg.seenBy || []);
    const allSeen = otherMembers.every(id => seenBy.has(id));

    return allSeen ? 'Seen' : 'Sent';
  };

  const SidebarContent = () => (
    <div className="flex flex-col h-full bg-zinc-950">
      <div className="p-3 sm:p-4 md:p-6 border-b border-zinc-900 flex items-center justify-between">
        <div className="flex items-center space-x-2 sm:space-x-3 min-w-0">
          <div className="p-1.5 sm:p-2 rounded-lg sm:rounded-xl bg-zinc-900 border border-zinc-800 shrink-0">
            <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-zinc-100" />
          </div>
          <h1 className="font-bold text-base sm:text-lg md:text-xl tracking-tight truncate">E2EE Chat</h1>
        </div>
        <Sheet>
          <SheetTrigger className="p-1.5 sm:p-2 rounded-full hover:bg-zinc-900 transition-colors">
            <Settings className="w-4 h-4 sm:w-5 sm:h-5 text-zinc-400" />
          </SheetTrigger>
          <SheetContent side="left" className="bg-zinc-950 border-zinc-900 text-zinc-50">
            <SheetHeader>
              <SheetTitle className="text-zinc-100">Settings</SheetTitle>
            </SheetHeader>
            <div className="py-4 sm:py-6 md:py-8 space-y-4 sm:space-y-6">
              <div className="flex items-center space-x-2 sm:space-x-4 p-3 sm:p-4 rounded-xl sm:rounded-2xl bg-zinc-900/50 border border-zinc-800">
                <Avatar className="w-10 h-10 sm:w-12 sm:h-12 border-2 border-zinc-800 shrink-0">
                  <AvatarImage src={user.photoURL || ''} />
                  <AvatarFallback className="bg-zinc-800 text-zinc-400">
                    {user.displayName?.[0] || 'U'}
                  </AvatarFallback>
                </Avatar>
                <div className="min-w-0 flex-1">
                  <p className="font-semibold text-sm sm:text-base text-zinc-100 truncate">{user.displayName}</p>
                  <p className="text-[10px] text-zinc-500 truncate">{user.email}</p>
                </div>
              </div>
              
              <div className="space-y-3 sm:space-y-4">
                <p className="text-[9px] sm:text-xs font-medium text-zinc-500 uppercase tracking-wider px-2">Account Info</p>
                <div className="p-3 sm:p-4 rounded-xl sm:rounded-2xl bg-zinc-900/50 border border-zinc-800 space-y-2 sm:space-y-3">
                  <div>
                    <p className="text-[9px] text-zinc-500 mb-1">Your UID</p>
                    <p className="text-[9px] font-mono text-zinc-400 break-all bg-zinc-950 p-2 rounded-lg border border-zinc-800">{user.uid}</p>
                  </div>
                  <div>
                    <p className="text-[9px] text-zinc-500 mb-1">Your Email</p>
                    <p className="text-[9px] font-mono text-zinc-400 break-all bg-zinc-950 p-2 rounded-lg border border-zinc-800">{user.email}</p>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={refreshProfile}
                    disabled={loading}
                    className="w-full border-zinc-800 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100 h-8 text-[9px] sm:text-[10px]"
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
          <ScrollArea className="flex-1 h-0 px-2">
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

          <ScrollArea className="flex-1 h-0 px-2">
            <div className="space-y-1 p-2">
              {allUsers
                .filter(u => u.uid !== user.uid && (u.email?.includes(userSearchQuery) || u.uid.includes(userSearchQuery)))
                .map(u => (
                <div
                  key={u.uid}
                  className="flex items-center justify-between p-2 rounded-xl hover:bg-zinc-900 transition-colors group"
                >
                  <div className="flex items-center space-x-3 overflow-hidden">
                    <div className="relative">
                      <Avatar className="w-8 h-8 border border-zinc-800">
                        <AvatarFallback className="bg-zinc-800 text-[10px] text-zinc-500">
                          {u.email?.[0].toUpperCase() || 'U'}
                        </AvatarFallback>
                      </Avatar>
                      <div className={`absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full border-2 border-zinc-950 ${getStatusColor(userStatusMap[u.id]?.status || 'inactive')}`} />
                    </div>
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
      <div className="flex-1 flex flex-col bg-zinc-950 min-w-0 min-h-0 relative">
        {activeRoom ? (
          <>
            {/* Chat Header */}
            <div className="p-3 sm:p-4 md:p-6 border-b border-zinc-900 bg-zinc-950/50 backdrop-blur-xl flex items-center justify-between sticky top-0 z-10">
              <div className="flex items-center space-x-4 overflow-hidden">
                <Button 
                  variant="ghost" 
                  size="icon" 
                  className="md:hidden text-zinc-400"
                  onClick={() => {
                    setActiveRoom(null);
                    setShowMobileSidebar(true);
                  }}
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
                          {activeRoom.members.map(m => {
                            const memberData = allUsers.find(u => u.id === m);
                            const memberStatus = userStatusMap[m]?.status || 'inactive';
                            const memberPresence = getMemberPresenceLabel(m);
                            return (
                              <div key={m} className="flex items-center justify-between p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
                                <div className="flex items-center space-x-2 overflow-hidden flex-1">
                                  <div className="relative">
                                    <Avatar className="w-6 h-6 border border-zinc-800 shrink-0">
                                      <AvatarFallback className="bg-zinc-800 text-[8px] text-zinc-500">
                                        {memberData?.email?.[0].toUpperCase() || 'U'}
                                      </AvatarFallback>
                                    </Avatar>
                                    <div className={`absolute bottom-0 right-0 w-2 h-2 rounded-full border border-zinc-950 ${getStatusColor(memberStatus)}`} />
                                  </div>
                                  <div className="overflow-hidden flex-1">
                                    <p className="text-xs font-semibold text-zinc-100 truncate">{m === user.uid ? 'You' : 'Anonymous'}</p>
                                    <p className="text-[10px] text-zinc-500">{memberPresence}</p>
                                  </div>
                                </div>
                                {m === user.uid && <Badge className="bg-zinc-800 text-zinc-400 text-[10px] shrink-0">You</Badge>}
                              </div>
                            );
                          })}
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
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleDeleteRoom}
                  disabled={loading}
                  className="text-red-400 hover:bg-red-500/10"
                  aria-label="Delete room"
                >
                  <Trash2 className="w-5 h-5" />
                </Button>
              </div>
            </div>

            {activeRoom.pinHash && !roomPinVerified[activeRoom.id] ? (
              <div className="p-6 mx-4 mt-4 rounded-3xl border border-red-500 bg-red-500/10 text-red-200 text-center">
                <p className="text-sm font-semibold">Room PIN required</p>
                <p className="text-xs text-red-300 mt-2 mb-4">Enter the 4-digit PIN to unlock this encrypted room. Messages will remain hidden until the correct code is entered.</p>
                <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                  <Input
                    type="password"
                    inputMode="numeric"
                    maxLength={4}
                    value={roomPinInput}
                    onChange={(e) => setRoomPinInput(e.target.value.replace(/[^0-9]/g, '').slice(0, 4))}
                    placeholder="PIN"
                    className="w-full max-w-[140px] bg-zinc-900 border-zinc-800 text-zinc-100"
                  />
                  <Button
                    onClick={async () => {
                      if (!roomPinInput || roomPinInput.length !== 4) {
                        setPinError('Enter a valid 4-digit PIN.');
                        return;
                      }
                      const success = await verifyRoomPinForRoom(roomPinInput);
                      if (success) {
                        toast.success('Room unlocked.');
                      }
                    }}
                    disabled={loading || roomPinAttempts[activeRoom.id] >= MAX_PIN_ATTEMPTS}
                    className="bg-zinc-100 text-zinc-950 hover:bg-zinc-200"
                  >
                    Unlock
                  </Button>
                </div>
                {pinError ? <p className="mt-2 text-[11px] text-red-300">{pinError}</p> : null}
                {roomPinAttempts[activeRoom.id] >= MAX_PIN_ATTEMPTS ? (
                  <p className="mt-2 text-[11px] text-red-300">Room locked after 3 failed PIN attempts.</p>
                ) : null}
              </div>
            ) : null}

            {/* Messages Area */}
            <ScrollArea ref={messagesScrollAreaRef} className="flex-1 h-0 p-2 sm:p-3 md:p-8 overscroll-contain">
              <div className="max-w-4xl mx-auto space-y-3 sm:space-y-4 md:space-y-8 pb-4">
                {messages.map((msg, i) => {
                  const isMine = msg.senderId === user.uid;
                  const prevMsg = messages[i - 1];
                  const showAvatar = !prevMsg || prevMsg.senderId !== msg.senderId;
                  
                  let fileData = null;
                  let locationData = null;
                  if (msg.decryptedText?.startsWith('{')) {
                    try {
                      const parsed = JSON.parse(msg.decryptedText);
                      if (parsed.type === 'file') fileData = parsed;
                      if (parsed.type === 'location') locationData = parsed;
                    } catch (e) {}
                  }

                  return (
                    <div key={msg.id} className={`flex items-end space-x-1.5 sm:space-x-2 md:space-x-4 ${isMine ? 'flex-row-reverse space-x-reverse' : ''}`}>
                      <div className={`w-5 h-5 sm:w-6 sm:h-6 md:w-10 md:h-10 shrink-0 ${!showAvatar ? 'opacity-0' : ''}`}>
                        <Avatar className="w-full h-full border-2 border-zinc-900">
                          <AvatarFallback className="bg-zinc-900 text-[10px] md:text-xs text-zinc-500">
                            {isMine ? 'Me' : 'A'}
                          </AvatarFallback>
                        </Avatar>
                      </div>
                      
                      <div className={`flex flex-col max-w-[80%] sm:max-w-[75%] md:max-w-[70%] ${isMine ? 'items-end' : 'items-start'}`}>
                        {showAvatar && (
                          <span className="text-[9px] sm:text-[10px] text-zinc-600 mb-0.5 sm:mb-1 px-1 font-mono">
                            {isMine ? 'You' : 'Anonymous'}
                          </span>
                        )}
                        
                        <div className={`group relative p-2 sm:p-3 md:p-4 rounded-xl sm:rounded-2xl md:rounded-3xl ${
                          isMine 
                            ? 'bg-zinc-100 text-zinc-950 rounded-tr-none' 
                            : 'bg-zinc-900 text-zinc-100 rounded-tl-none border border-zinc-800'
                        }`}>
                          {fileData ? (
                            <div className="flex flex-col space-y-2">
                              <div className="flex items-center space-x-2 sm:space-x-3">
                                <div className={`p-1.5 sm:p-2 md:p-3 rounded-lg sm:rounded-xl ${isMine ? 'bg-zinc-200' : 'bg-zinc-800'}`}>
                                  <Paperclip className="w-3.5 h-3.5 sm:w-4 sm:h-4 md:w-5 md:h-5" />
                                </div>
                                <div className="overflow-hidden min-w-0">
                                  <p className="text-[10px] sm:text-xs md:text-sm font-semibold truncate">{fileData.name}</p>
                                  <p className="text-[9px] text-zinc-500 truncate max-w-[220px]">{fileData.mimeType || 'Encrypted file'}</p>
                                </div>
                              </div>
                              <Button 
                                variant="secondary" 
                                size="sm" 
                                className="w-full justify-center text-[9px] sm:text-[10px] md:text-xs"
                                onClick={() => handleDownloadEncryptedFile(fileData)}
                              >
                                <Download className="w-3 h-3 mr-1" />
                                Download Securely
                              </Button>
                            </div>
                          ) : locationData ? (
                            <a
                              href={`https://www.google.com/maps?q=${encodeURIComponent(`${locationData.latitude},${locationData.longitude}`)}`}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 hover:bg-slate-900"
                            >
                              <MapPin className="w-3.5 h-3.5 mr-2" />
                              <span>{locationData.label || 'Shared location'}</span>
                            </a>
                          ) : (
                            <p className="text-[13px] sm:text-xs md:text-sm leading-relaxed whitespace-pre-wrap break-words">
                              {msg.decryptedText}
                            </p>
                          )}
                          
                          <div className={`absolute bottom-0 ${isMine ? '-left-12' : '-right-12'} opacity-0 group-hover:opacity-100 transition-opacity`}>
                            <div className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 shadow-xl">
                              <Shield className="w-3 h-3 text-emerald-500" />
                            </div>
                          </div>
                        </div>
                        
                        <span className="text-[9px] sm:text-[10px] text-zinc-600 mt-1 sm:mt-1.5 px-1 flex items-center space-x-2">
                          <span>{msg.createdAt?.toDate ? format(msg.createdAt.toDate(), 'HH:mm') : '...'}</span>
                          {msg.isMine ? (
                            <span className="rounded-full bg-zinc-900 px-2 py-0.5 text-[9px] text-zinc-400 uppercase tracking-[0.08em]">
                              {getMessageStatus(msg)}
                            </span>
                          ) : null}
                        </span>
                      </div>
                    </div>
                  );
                })}
                <div ref={scrollRef} />
              </div>
            </ScrollArea>

            {showJumpToBottom && (
              <div className="absolute right-4 top-24 z-20">
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={scrollToBottom}
                  className="shadow-xl bg-zinc-900/95 text-zinc-100 hover:bg-zinc-800"
                >
                  Scroll to current messages
                </Button>
              </div>
            )}

            {/* Input Area */}
            <div className="p-2 sm:p-3 md:p-8 border-t border-zinc-900 bg-zinc-950/50 backdrop-blur-xl">
              <div className="max-w-4xl mx-auto">
                <div className="relative flex items-end space-x-1.5 sm:space-x-2 md:space-x-4 bg-zinc-900/50 border border-zinc-800 p-1.5 sm:p-2 md:p-3 rounded-xl sm:rounded-2xl md:rounded-3xl focus-within:border-zinc-700 transition-colors shadow-inner">
                  <div className="flex items-center space-x-2">
                    <input
                      type="file"
                      ref={fileInputRef}
                      accept="image/*,video/*,*/*"
                      id="file-upload"
                      className="hidden"
                      onChange={handleFileUpload}
                      disabled={!!activeRoom?.pinHash && !roomPinVerified[activeRoom.id]}
                    />
                    <label htmlFor="file-upload" className="cursor-pointer h-9 w-9 sm:h-10 sm:w-10 md:h-12 md:w-12 flex items-center justify-center rounded-lg sm:rounded-xl md:rounded-2xl text-zinc-500 hover:text-zinc-100 hover:bg-zinc-800 transition-colors active:scale-95">
                      <Paperclip className="w-4 h-4 sm:w-5 sm:h-5 md:w-6 md:h-6" />
                    </label>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={handleSendLocation}
                      disabled={loading || !roomKeys[activeRoom.id] || (!!activeRoom?.pinHash && !roomPinVerified[activeRoom.id])}
                      className="h-9 w-9 sm:h-10 sm:w-10 md:h-12 md:w-12 rounded-lg sm:rounded-xl md:rounded-2xl text-zinc-500 hover:text-zinc-100 hover:bg-zinc-800 transition-colors active:scale-95"
                      aria-label="Send location"
                    >
                      <MapPin className="w-4 h-4 sm:w-5 sm:h-5 md:w-6 md:h-6" />
                    </Button>
                  </div>
                  
                  <textarea
                    rows={1}
                    value={newMessage}
                    onChange={(e) => {
                      setNewMessage(e.target.value);
                      e.currentTarget.style.height = 'auto';
                      e.currentTarget.style.height = Math.min(e.currentTarget.scrollHeight, 128) + 'px';
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        handleSendMessage();
                      }
                    }}
                    placeholder={activeRoom?.pinHash && !roomPinVerified[activeRoom.id] ? "Enter room PIN to unlock." : (!roomKeys[activeRoom.id] ? "Waiting for secure key..." : "Type a message...")}
                    disabled={!roomKeys[activeRoom.id] || (!!activeRoom?.pinHash && !roomPinVerified[activeRoom.id])}
                    className="flex-1 bg-transparent border-none focus:ring-0 text-zinc-100 placeholder:text-zinc-600 resize-none py-2 sm:py-2.5 md:py-3.5 px-1 sm:px-2 text-[13px] sm:text-sm md:text-base max-h-32 min-h-[36px]"
                  />
                  
                  <Button 
                    size="icon"
                    onClick={handleSendMessage}
                    disabled={!newMessage.trim() || loading || !roomKeys[activeRoom.id] || (!!activeRoom?.pinHash && !roomPinVerified[activeRoom.id])}
                    className="h-9 w-9 sm:h-10 sm:w-10 md:h-12 md:w-12 rounded-lg sm:rounded-xl md:rounded-2xl bg-zinc-100 text-zinc-950 hover:bg-zinc-200 shrink-0 shadow-lg active:scale-95 transition-transform"
                  >
                    {loading ? <Loader2 className="w-4 h-4 sm:w-5 sm:h-5 animate-spin" /> : <Send className="w-4 h-4 sm:w-5 sm:h-5 md:w-6 md:h-6" />}
                  </Button>
                </div>
                <div className="mt-2 sm:mt-3 flex items-center justify-center space-x-1.5 sm:space-x-2">
                  <Shield className="w-2.5 h-2.5 sm:w-3 sm:h-3 text-emerald-500/50 shrink-0" />
                  <p className="text-[9px] sm:text-[10px] text-zinc-600 font-medium uppercase tracking-wider">
                    Encrypted
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
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Room PIN</label>
                    <Input
                      placeholder="4-digit PIN"
                      value={newRoomPin}
                      onChange={(e) => setNewRoomPin(e.target.value.replace(/[^0-9]/g, '').slice(0, 4))}
                      className="bg-zinc-950 border-zinc-800"
                      maxLength={4}
                    />
                    {pinError ? <p className="text-[10px] text-red-500">{pinError}</p> : null}
                  </div>
                  <div className="p-3 rounded-lg bg-zinc-950/50 border border-zinc-800 flex items-start space-x-3">
                    <Shield className="w-4 h-4 mt-0.5 text-emerald-500" />
                    <p className="text-[10px] text-zinc-500 leading-relaxed">
                      A unique symmetric key will be generated for this room and shared securely with members. PIN access is required for all participants.
                    </p>
                  </div>
                </CardContent>
                <div className="p-6 pt-0 flex justify-end space-x-2">
                  <Button variant="ghost" onClick={() => setIsCreatingRoom(false)} className="text-zinc-500">Cancel</Button>
                  <Button 
                    onClick={handleCreateRoom} 
                    disabled={!newRoomName || !newRoomPin || newRoomPin.length !== 4 || loading || !isSodiumReady}
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
