import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, onAuthStateChanged, User as FirebaseUser, signInWithEmailAndPassword, createUserWithEmailAndPassword } from 'firebase/auth';
import { getFirestore, collection, doc, setDoc, getDoc, getDocs, query, where, onSnapshot, addDoc, serverTimestamp, Timestamp, orderBy, limit, updateDoc, arrayUnion, writeBatch } from 'firebase/firestore';
import { getStorage, ref, uploadBytes, getDownloadURL } from 'firebase/storage';
import firebaseConfig from '../firebase-applet-config.json';

// Initialize Firebase SDK
const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);
export const storage = getStorage(app);
export const googleProvider = new GoogleAuthProvider();

// --- Auth Utils ---

export async function signIn() {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    return result.user;
  } catch (error) {
    console.error('Sign in error:', error);
    throw error;
  }
}

export async function signInEmail(email: string, pass: string) {
  try {
    const result = await signInWithEmailAndPassword(auth, email, pass);
    return result.user;
  } catch (error) {
    console.error('Email sign in error:', error);
    throw error;
  }
}

export async function signUpEmail(email: string, pass: string) {
  try {
    const result = await createUserWithEmailAndPassword(auth, email, pass);
    return result.user;
  } catch (error) {
    console.error('Email sign up error:', error);
    throw error;
  }
}

export function signOut() {
  return auth.signOut();
}

// --- Firestore Utils with Error Handling ---

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId: string | undefined;
    email: string | null | undefined;
    emailVerified: boolean | undefined;
    isAnonymous: boolean | undefined;
    tenantId: string | null | undefined;
    providerInfo: {
      providerId: string;
      displayName: string | null;
      email: string | null;
      photoUrl: string | null;
    }[];
  }
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null) {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo: auth.currentUser?.providerData.map(provider => ({
        providerId: provider.providerId,
        displayName: provider.displayName,
        email: provider.email,
        photoUrl: provider.photoURL
      })) || []
    },
    operationType,
    path
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// --- Data Fetching ---

export { collection, doc, setDoc, getDoc, getDocs, query, where, onSnapshot, addDoc, serverTimestamp, Timestamp, orderBy, limit, onAuthStateChanged, updateDoc, arrayUnion, writeBatch };
