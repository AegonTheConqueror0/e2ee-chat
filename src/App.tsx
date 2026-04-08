import { useState, useEffect } from 'react';
import { auth, onAuthStateChanged, db, doc, getDoc, setDoc, serverTimestamp } from '@/firebase';
import { User as FirebaseUser } from 'firebase/auth';
import { initSodium, loadKeysLocally, IdentityKeys, generateIdentityKeys, saveKeysLocally, toBase64 } from '@/lib/crypto';
import { Toaster } from '@/components/ui/sonner';
import { toast } from 'sonner';
import Auth from '@/components/Auth';
import Setup from '@/components/Setup';
import Chat from '@/components/Chat';
import { Loader2, AlertTriangle } from 'lucide-react';

export default function App() {
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [keys, setKeys] = useState<IdentityKeys | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [backupAvailable, setBackupAvailable] = useState(false);
  const [existingIdentity, setExistingIdentity] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Add a timeout to prevent endless loading
    const loadingTimeout = setTimeout(() => {
      if (loading) {
        console.error('Loading timeout reached - Firebase initialization may have failed');
        setError('Loading timeout - Firebase may not be initializing properly. Check console for details.');
        setLoading(false);
      }
    }, 30000); // 30 second timeout

    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      try {
        console.log('Auth state changed:', firebaseUser ? 'user logged in' : 'no user');
        setUser(firebaseUser);
        setIsAuthReady(true);
        
        if (firebaseUser) {
          console.log('Initializing sodium...');
          await initSodium();
          console.log('Sodium initialized successfully');
          
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
          const backupDoc = await getDoc(doc(db, 'backups', firebaseUser.uid));
          setBackupAvailable(backupDoc.exists());

          const hasKeys = Boolean(userDoc.exists() && userDoc.data()?.publicKeySigning && userDoc.data()?.publicKeyExchange);
          setExistingIdentity(hasKeys);

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
        clearTimeout(loadingTimeout);
      } catch (err) {
        console.error('Error during auth state change:', err);
        setError(`Initialization failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
        setLoading(false);
        clearTimeout(loadingTimeout);
      }
    });

    return () => {
      unsubscribe();
      clearTimeout(loadingTimeout);
    };
  }, []);

  const handleKeysGenerated = async (newKeys: IdentityKeys) => {
    try {
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
    } catch (err) {
      console.error('Error generating keys:', err);
      toast.error('Failed to save identity keys');
    }
  };

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-zinc-950 text-zinc-50 p-4">
        <div className="max-w-md w-full bg-zinc-900 border border-red-500/20 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <AlertTriangle className="w-6 h-6 text-red-400" />
            <h2 className="text-lg font-semibold text-red-400">Initialization Error</h2>
          </div>
          <p className="text-zinc-300 mb-4">{error}</p>
          <p className="text-sm text-zinc-500">
            Check the browser console for more details and ensure Firebase configuration is correct.
          </p>
        </div>
      </div>
    );
  }

  if (loading || !isAuthReady) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-zinc-950 text-zinc-50">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin text-zinc-400 mx-auto mb-4" />
          <p className="text-zinc-400">Initializing...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 font-sans selection:bg-zinc-800">
      <Toaster position="top-center" theme="dark" />
      
      {!user ? (
        <Auth />
      ) : !keys ? (
        <Setup
          onKeysGenerated={handleKeysGenerated}
          user={user}
          backupAvailable={backupAvailable}
          existingIdentity={existingIdentity}
        />
      ) : (
        <Chat user={user} keys={keys} />
      )}
    </div>
  );
}
