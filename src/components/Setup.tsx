import { useState } from 'react';
import { generateIdentityKeys, IdentityKeys, backupKeys, restoreKeys, fromBase64 } from '@/lib/crypto';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Shield, Key, Download, Upload, Loader2, AlertCircle } from 'lucide-react';
import { User as FirebaseUser } from 'firebase/auth';
import { db, doc, setDoc, getDoc } from '@/firebase';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'motion/react';

interface SetupProps {
  onKeysGenerated: (keys: IdentityKeys) => void;
  user: FirebaseUser;
}

export default function Setup({ onKeysGenerated, user }: SetupProps) {
  const [step, setStep] = useState<'initial' | 'generate' | 'backup' | 'restore'>('initial');
  const [passphrase, setPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const keys = await generateIdentityKeys();
      onKeysGenerated(keys);
    } catch (err) {
      setError('Failed to generate keys.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleBackup = async () => {
    if (passphrase.length < 8) {
      toast.error('Passphrase must be at least 8 characters.');
      return;
    }
    setLoading(true);
    try {
      const keys = await generateIdentityKeys();
      const backup = await backupKeys(keys, passphrase);
      
      // Store backup in Firestore
      await setDoc(doc(db, 'backups', user.uid), {
        userId: user.uid,
        ciphertext: backup.ciphertext,
        nonce: backup.nonce,
        salt: backup.salt,
      });
      
      onKeysGenerated(keys);
      toast.success('Keys generated and backed up successfully.');
    } catch (err) {
      setError('Failed to backup keys.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRestore = async () => {
    setLoading(true);
    try {
      const backupDoc = await getDoc(doc(db, 'backups', user.uid));
      if (!backupDoc.exists()) {
        toast.error('No backup found for this account.');
        setLoading(false);
        return;
      }
      
      const userDoc = await getDoc(doc(db, 'users', user.uid));
      if (!userDoc.exists()) {
        toast.error('User profile not found.');
        setLoading(false);
        return;
      }

      const backupData = backupDoc.data() as any;
      const userData = userDoc.data() as any;
      
      const publicKeys = {
        signing: fromBase64(userData.publicKeySigning),
        exchange: fromBase64(userData.publicKeyExchange),
      };

      const keys = await restoreKeys(backupData, passphrase, publicKeys);
      onKeysGenerated(keys);
      toast.success('Keys restored successfully.');
    } catch (err) {
      toast.error('Failed to restore keys. Check your passphrase.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen p-4 bg-zinc-950">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-md"
      >
        <Card className="border-zinc-800 bg-zinc-900/50 backdrop-blur-xl shadow-2xl overflow-hidden">
          <CardHeader className="space-y-1">
            <div className="flex items-center space-x-2 mb-2">
              <div className="p-2 rounded-lg bg-zinc-800 border border-zinc-700">
                <Key className="w-5 h-5 text-zinc-100" />
              </div>
              <CardTitle className="text-xl">Security Setup</CardTitle>
            </div>
            <CardDescription className="text-zinc-400">
              {step === 'initial' && 'Choose how to set up your identity keys.'}
              {step === 'generate' && 'Generate new keys for this device.'}
              {step === 'backup' && 'Create a passphrase to backup your keys.'}
              {step === 'restore' && 'Enter your passphrase to restore your keys.'}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4 py-6">
            <AnimatePresence mode="wait">
              {step === 'initial' && (
                <motion.div
                  key="initial"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  className="space-y-4"
                >
                  <Button
                    onClick={() => setStep('backup')}
                    className="w-full h-14 justify-start space-x-4 bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border-zinc-700"
                  >
                    <Download className="w-5 h-5 text-zinc-400" />
                    <div className="text-left">
                      <p className="text-sm font-semibold">Generate New Keys</p>
                      <p className="text-xs text-zinc-500 font-normal">Create and backup a new identity.</p>
                    </div>
                  </Button>
                  <Button
                    onClick={() => setStep('restore')}
                    variant="outline"
                    className="w-full h-14 justify-start space-x-4 border-zinc-800 hover:bg-zinc-900 text-zinc-300"
                  >
                    <Upload className="w-5 h-5 text-zinc-500" />
                    <div className="text-left">
                      <p className="text-sm font-semibold">Restore from Backup</p>
                      <p className="text-xs text-zinc-500 font-normal">Use your existing keys on this device.</p>
                    </div>
                  </Button>
                  <Button
                    onClick={handleGenerate}
                    variant="ghost"
                    className="w-full text-zinc-500 hover:text-zinc-300 hover:bg-transparent"
                  >
                    Generate without backup (Not recommended)
                  </Button>
                </motion.div>
              )}

              {(step === 'backup' || step === 'restore') && (
                <motion.div
                  key="form"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="space-y-4"
                >
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-zinc-500 uppercase tracking-wider">
                      Passphrase
                    </label>
                    <Input
                      type="password"
                      placeholder="Enter a strong passphrase"
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                      className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:ring-zinc-700"
                    />
                  </div>
                  <div className="p-3 rounded-lg bg-zinc-900/80 border border-zinc-800 flex items-start space-x-3">
                    <AlertCircle className="w-4 h-4 mt-0.5 text-zinc-500" />
                    <p className="text-xs text-zinc-500 leading-relaxed">
                      Your passphrase is used to encrypt your private keys before they are uploaded to the server.
                      We cannot recover your keys if you lose this passphrase.
                    </p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </CardContent>

          <CardFooter className="flex justify-between border-t border-zinc-800 bg-zinc-900/30 pt-6">
            {step !== 'initial' && (
              <Button
                variant="ghost"
                onClick={() => setStep('initial')}
                disabled={loading}
                className="text-zinc-500 hover:text-zinc-300"
              >
                Back
              </Button>
            )}
            <div className="flex-1" />
            {step === 'backup' && (
              <Button
                onClick={handleBackup}
                disabled={loading || passphrase.length < 8}
                className="bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Generate & Backup'}
              </Button>
            )}
            {step === 'restore' && (
              <Button
                onClick={handleRestore}
                disabled={loading || passphrase.length < 8}
                className="bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Restore Keys'}
              </Button>
            )}
          </CardFooter>
        </Card>
      </motion.div>
    </div>
  );
}
