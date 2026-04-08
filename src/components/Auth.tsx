import { signIn, signInEmail, signUpEmail } from '@/firebase';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Shield, Lock, Key, MessageSquare, Mail, Lock as LockIcon, Loader2 } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import React, { useState } from 'react';

export default function Auth() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSignUp, setIsSignUp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGoogleSignIn = async () => {
    if (loading) return;
    setLoading(true);
    setError(null);
    try {
      await signIn();
    } catch (err: any) {
      console.error('Sign in failed:', err);
      if (err.code === 'auth/popup-closed-by-user') {
        setError('Sign-in popup was closed.');
      } else if (err.code === 'auth/popup-blocked') {
        setError('Sign-in popup was blocked by your browser. Please allow popups for this site.');
      } else if (err.code === 'auth/unauthorized-domain') {
        setError(`Domain not authorized. Please add "${window.location.hostname}" to Authorized Domains in Firebase Console.`);
      } else if (err.code === 'auth/operation-not-allowed') {
        setError('Google Sign-In is not enabled in your Firebase Console.');
      } else {
        setError(err.message || 'Google sign in failed.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password || loading) return;
    
    setLoading(true);
    setError(null);
    try {
      if (isSignUp) {
        await signUpEmail(email, password);
      } else {
        await signInEmail(email, password);
      }
    } catch (err: any) {
      console.error('Email auth failed:', err);
      if (err.code === 'auth/invalid-credential' || err.code === 'auth/user-not-found' || err.code === 'auth/wrong-password') {
        setError('Password or Email incorrect');
      } else if (err.code === 'auth/email-already-in-use') {
        setError('Email already in use.');
      } else if (err.code === 'auth/weak-password') {
        setError('Password should be at least 6 characters.');
      } else if (err.code === 'auth/operation-not-allowed') {
        setError('Email/Password auth is DISABLED. Please enable it in Firebase Console > Authentication > Sign-in method.');
      } else {
        setError(err.message || 'Authentication failed.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen p-4 bg-zinc-950">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        <div className="flex flex-col items-center mb-8 space-y-2 text-center">
          <div className="p-3 mb-4 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-xl">
            <Shield className="w-10 h-10 text-zinc-100" />
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-zinc-50">E2EE Chat</h1>
          <p className="text-zinc-400">Secure, private, and metadata-minimized.</p>
        </div>

        <Card className="border-zinc-800 bg-zinc-900/50 backdrop-blur-xl shadow-2xl">
          <CardHeader>
            <CardTitle className="text-xl text-zinc-100">
              {isSignUp ? 'Create Account' : 'Welcome Back'}
            </CardTitle>
            <CardDescription className="text-zinc-400">
              {isSignUp 
                ? 'Sign up to start your secure conversations.' 
                : 'Sign in to access your secure conversations.'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <form onSubmit={handleEmailAuth} className="space-y-4">
              <div className="space-y-2">
                <div className="relative">
                  <Mail className="absolute left-3 top-3 w-4 h-4 text-zinc-500" />
                  <Input
                    type="email"
                    placeholder="Email address"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-10 bg-zinc-900/50 border-zinc-800 text-zinc-100 placeholder:text-zinc-600 focus:ring-zinc-700"
                    required
                  />
                </div>
              </div>
              <div className="space-y-2">
                <div className="relative">
                  <LockIcon className="absolute left-3 top-3 w-4 h-4 text-zinc-500" />
                  <Input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pl-10 bg-zinc-900/50 border-zinc-800 text-zinc-100 placeholder:text-zinc-600 focus:ring-zinc-700"
                    required
                  />
                </div>
              </div>

              <AnimatePresence mode="wait">
                {error && (
                  <motion.p
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="text-sm font-medium text-red-500 text-center"
                  >
                    {error}
                  </motion.p>
                )}
              </AnimatePresence>

              <Button
                type="submit"
                disabled={loading}
                className="w-full h-11 text-base font-semibold bg-zinc-50 text-zinc-950 hover:bg-zinc-200 transition-all duration-200 rounded-xl"
              >
                {loading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  isSignUp ? 'Sign Up' : 'Sign In'
                )}
              </Button>
            </form>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-zinc-800" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-zinc-950 px-2 text-zinc-500">Or continue with</span>
              </div>
            </div>

            <Button
              onClick={handleGoogleSignIn}
              disabled={loading}
              variant="outline"
              className="w-full h-11 border-zinc-800 bg-transparent text-zinc-300 hover:bg-zinc-900 hover:text-zinc-100 transition-all duration-200 rounded-xl"
            >
              <svg className="mr-2 h-4 w-4" aria-hidden="true" focusable="false" data-prefix="fab" data-icon="google" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 488 512">
                <path fill="currentColor" d="M488 261.8C488 403.3 391.1 504 248 504 110.8 504 0 393.2 0 256S110.8 8 248 8c66.8 0 123 24.5 166.3 64.9l-67.5 64.9C258.5 52.6 94.3 116.6 94.3 256c0 86.5 69.1 156.6 153.7 156.6 98.2 0 135-70.4 140.8-106.9H248v-85.3h236.1c2.3 12.7 3.9 24.9 3.9 41.4z"></path>
              </svg>
              Google
            </Button>

            <div className="text-center">
              <button
                onClick={() => setIsSignUp(!isSignUp)}
                className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                {isSignUp ? 'Already have an account? Sign In' : "Don't have an account? Sign Up"}
              </button>
            </div>
          </CardContent>
        </Card>

        <p className="mt-8 text-center text-xs text-zinc-600">
          By signing in, you agree to our security model. Your private keys will be stored locally on this device.
        </p>
      </motion.div>
    </div>
  );
}
