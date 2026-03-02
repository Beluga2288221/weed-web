/**
 * Firebase Authentication with Email
 * Security: Backend validation on auth.php
 */

// ── FIREBASE CONFIG ──
const firebaseConfig = {
  apiKey: "AIzaSyDwGZJiXndq9XrU8T6skIZ0oLaN15yzg4o",
  authDomain: "weed-79be3.firebaseapp.com",
  projectId: "weed-79be3",
  storageBucket: "weed-79be3.firebasestorage.app",
  messagingSenderId: "884687153479",
  appId: "1:884687153479:web:ff783e1de709a4a8188462",
  measurementId: "G-19LBX5TW0M"
};

// Initialize Firebase
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-auth.js";
import { getFirestore, collection, doc, setDoc, getDoc } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore.js";

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// ── BACKEND VALIDATION ──
async function validateWithBackend(action, data) {
  try {
    const response = await fetch(`/auth.php?action=${action}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });

    return await response.json();
  } catch (error) {
    console.error('Backend validation error:', error);
    throw new Error('Backend connection failed');
  }
}

// ── REGISTER ──
export async function registerUser(email, name, password) {
  try {
    // 1. Validate on backend first
    const validation = await validateWithBackend('register', {
      email,
      name,
      password
    });

    if (!validation.success) {
      throw new Error(validation.error || 'Registration validation failed');
    }

    // 2. Create user in Firebase
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    const uid = userCredential.user.uid;

    // 3. Store user data in Firestore
    await setDoc(doc(db, 'users', uid), {
      uid,
      email,
      name,
      createdAt: new Date(),
      lastLogin: new Date(),
      verified: false
    });

    return { success: true, user: userCredential.user };
  } catch (error) {
    console.error('Registration error:', error);
    throw error;
  }
}

// ── LOGIN ──
export async function loginUser(email, password) {
  try {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    
    // Update last login
    const uid = userCredential.user.uid;
    await setDoc(doc(db, 'users', uid), {
      lastLogin: new Date()
    }, { merge: true });

    return { success: true, user: userCredential.user };
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
}

// ── LOGOUT ──
export async function logoutUser() {
  try {
    await signOut(auth);
    return { success: true };
  } catch (error) {
    console.error('Logout error:', error);
    throw error;
  }
}

// ── GET CURRENT USER ──
export function getCurrentUser() {
  return new Promise((resolve) => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      unsubscribe();
      resolve(user);
    });
  });
}

// ── GET USER PROFILE ──
export async function getUserProfile(uid) {
  try {
    const docSnap = await getDoc(doc(db, 'users', uid));
    if (docSnap.exists()) {
      return docSnap.data();
    }
    return null;
  } catch (error) {
    console.error('Error getting profile:', error);
    throw error;
  }
}

// ── UPDATE USER PROFILE ──
export async function updateUserProfile(uid, data) {
  try {
    await setDoc(doc(db, 'users', uid), data, { merge: true });
    return { success: true };
  } catch (error) {
    console.error('Profile update error:', error);
    throw error;
  }
}

export { auth, db };
