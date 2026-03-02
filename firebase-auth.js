/**
 * Firebase Authentication with Email
 * Security: Firebase built-in + Firestore Security Rules
 */

// ── FIREBASE CONFIG ──
const firebaseConfig = {
  apiKey: "AIzaSyCVcSmwPF6XPup8L9AO-mmP3qQpXGO697w",
  authDomain: "weed-messenger-8200e.firebaseapp.com",
  projectId: "weed-messenger-8200e",
  storageBucket: "weed-messenger-8200e.firebasestorage.app",
  messagingSenderId: "165427827145",
  appId: "1:165427827145:web:a9fac6fec1b87f226e1818",
  measurementId: "G-BY7LCJ28RL"
};

// Initialize Firebase
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-auth.js";
import { getFirestore, collection, doc, setDoc, getDoc } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore.js";

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// ── VALIDATION FUNCTION ──
function validatePassword(password) {
  const errors = [];
  
  if (password.length < 8) {
    errors.push('Пароль должен быть минимум 8 символов');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Пароль должен содержать заглавную букву');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Пароль должен содержать цифру');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Пароль должен содержать строчную букву');
  }
  
  return {
    valid: errors.length === 0,
    errors: errors
  };
}

function validateEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

// ── REGISTER ──
export async function registerUser(email, name, password) {
  try {
    // 1. Validate email format
    if (!validateEmail(email)) {
      throw new Error('Invalid email format');
    }
    
    // 2. Validate name
    if (!name || name.length < 2 || name.length > 50) {
      throw new Error('Name must be 2-50 characters');
    }
    
    // 3. Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join('. '));
    }
    
    // 4. Create user in Firebase (Firebase handles rate limiting)
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    const uid = userCredential.user.uid;
    
    // 5. Update user profile
    await userCredential.user.updateProfile({
      displayName: name
    });

    // 6. Store user data in Firestore 
    // (Protected by Firestore Security Rules)
    await setDoc(doc(db, 'users', uid), {
      uid,
      email,
      name,
      createdAt: new Date(),
      lastLogin: new Date(),
      verified: false,
      online: true
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
