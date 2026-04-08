import { useState, useEffect } from 'react';
import { auth, onAuthStateChanged, db, doc, getDoc, setDoc, serverTimestamp } from '@/firebase';
import { User as FirebaseUser } from 'firebase/auth';
import { initSodium, loadKeysLocally, IdentityKeys, generateIdentityKeys, saveKeysLocally, toBase64 } from '@/lib/crypto';
import { Toaster } from '@/components/ui/sonner';
import { toast } from 'sonner';
import Auth from '@/components/Auth';
import Setup from '@/components/Setup';
import Chat from '@/components/Chat';
import { Loader2 } from 'lucide-react';

export default function App() {
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [keys, setKeys] = useState<IdentityKeys | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAuthReady, setIsAuthReady] = useState(false);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);
      setIsAuthReady(true);
      
      if (firebaseUser) {
        await initSodium();
        
        // Ensure user profile exists immediately for discoverability
        const userRef = doc(db, 'users', firebaseUser.uid);
        const userDoc = await getDoc(userRef);
        if (!userDoc.exists()) {
          try {
            await setDoc(userRef, {
              uid: firebaseUser.uid,
              email: firebaseUser.email?.toLowerCase(),
              createdAt: serverTimestamp(),
            });
          } catch (e) {
            console.error("Error creating initial profile:", e);
          }
        } else if (!userDoc.data().email) {
          await setDoc(userRef, { email: firebaseUser.email?.toLowerCase() }, { merge: true });
        }

        const localKeys = await loadKeysLocally();
        if (localKeys) {
          setKeys(localKeys);
          
          // Sync keys to Firestore if they exist locally
          const userRef = doc(db, 'users', firebaseUser.uid);
          await setDoc(userRef, {
            uid: firebaseUser.uid,
            email: firebaseUser.email?.toLowerCase(),
            publicKeySigning: toBase64(localKeys.signing.publicKey),
            publicKeyExchange: toBase64(localKeys.exchange.publicKey),
            lastActive: serverTimestamp(),
          }, { merge: true });
        }
      } else {
        setKeys(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const handleKeysGenerated = async (newKeys: IdentityKeys) => {
    setKeys(newKeys);
    await saveKeysLocally(newKeys);
    
    if (user) {
      // Update user profile with public keys
      const userRef = doc(db, 'users', user.uid);
      const userDoc = await getDoc(userRef);
      
      const publicKeys = {
        uid: user.uid,
        email: user.email?.toLowerCase(),
        publicKeySigning: toBase64(newKeys.signing.publicKey),
        publicKeyExchange: toBase64(newKeys.exchange.publicKey),
        createdAt: serverTimestamp(),
      };

      if (!userDoc.exists()) {
        await setDoc(userRef, publicKeys);
      } else {
        await setDoc(userRef, publicKeys, { merge: true });
      }
      toast.success('Identity keys generated and saved.');
    }
  };

  if (loading || !isAuthReady) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-zinc-950 text-zinc-50">
        <Loader2 className="w-8 h-8 animate-spin text-zinc-400" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 font-sans selection:bg-zinc-800">
      <Toaster position="top-center" theme="dark" />
      
      {!user ? (
        <Auth />
      ) : !keys ? (
        <Setup onKeysGenerated={handleKeysGenerated} user={user} />
      ) : (
        <Chat user={user} keys={keys} />
      )}
    </div>
  );
}
