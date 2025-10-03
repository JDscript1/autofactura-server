const crypto = require('crypto');

/**
 * Sistem de verificare umană (CAPTCHA) pentru AutoFactura
 * Implementează CAPTCHA simplu pentru a preveni spam-ul și atacurile automate
 */

// Întrebări și răspunsuri pentru CAPTCHA
const captchaQuestions = [
    {
        question: "Care este rezultatul: 5 + 3?",
        answer: "8",
        type: "math"
    },
    {
        question: "Care este rezultatul: 12 - 4?",
        answer: "8",
        type: "math"
    },
    {
        question: "Care este rezultatul: 2 × 4?",
        answer: "8",
        type: "math"
    },
    {
        question: "Care este rezultatul: 16 ÷ 2?",
        answer: "8",
        type: "math"
    },
    {
        question: "Care este rezultatul: 3 + 7?",
        answer: "10",
        type: "math"
    },
    {
        question: "Care este rezultatul: 15 - 6?",
        answer: "9",
        type: "math"
    },
    {
        question: "Care este rezultatul: 4 × 3?",
        answer: "12",
        type: "math"
    },
    {
        question: "Care este rezultatul: 20 ÷ 4?",
        answer: "5",
        type: "math"
    },
    {
        question: "Care este rezultatul: 6 + 9?",
        answer: "15",
        type: "math"
    },
    {
        question: "Care este rezultatul: 18 - 5?",
        answer: "13",
        type: "math"
    },
    {
        question: "Care este rezultatul: 7 × 2?",
        answer: "14",
        type: "math"
    },
    {
        question: "Care este rezultatul: 24 ÷ 3?",
        answer: "8",
        type: "math"
    },
    {
        question: "Care este rezultatul: 9 + 4?",
        answer: "13",
        type: "math"
    },
    {
        question: "Care este rezultatul: 17 - 8?",
        answer: "9",
        type: "math"
    },
    {
        question: "Care este rezultatul: 5 × 3?",
        answer: "15",
        type: "math"
    },
    {
        question: "Care este rezultatul: 30 ÷ 5?",
        answer: "6",
        type: "math"
    }
];

// Stocare temporară pentru CAPTCHA-uri active
let activeCaptchas = new Map();

/**
 * Generează un CAPTCHA nou
 * @returns {Object} Obiect cu question, token și expiresAt
 */
function generateCaptcha() {
    // Selectează o întrebare aleatorie
    const randomIndex = Math.floor(Math.random() * captchaQuestions.length);
    const selectedQuestion = captchaQuestions[randomIndex];
    
    // Generează un token unic
    const token = crypto.randomBytes(16).toString('hex');
    
    // Setează expirarea la 5 minute
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    
    // Stochează CAPTCHA-ul
    activeCaptchas.set(token, {
        question: selectedQuestion.question,
        answer: selectedQuestion.answer,
        type: selectedQuestion.type,
        expiresAt: expiresAt,
        attempts: 0
    });
    
    // Curăță CAPTCHA-urile expirate
    cleanupExpiredCaptchas();
    
    return {
        token: token,
        question: selectedQuestion.question,
        expiresAt: expiresAt.toISOString()
    };
}

/**
 * Verifică răspunsul CAPTCHA
 * @param {string} token - Token-ul CAPTCHA
 * @param {string} answer - Răspunsul utilizatorului
 * @returns {Object} Rezultatul verificării
 */
function verifyCaptcha(token, answer) {
    const captcha = activeCaptchas.get(token);
    
    if (!captcha) {
        return {
            success: false,
            error: 'Token CAPTCHA invalid sau expirat'
        };
    }
    
    // Verifică dacă CAPTCHA-ul a expirat
    if (new Date() > captcha.expiresAt) {
        activeCaptchas.delete(token);
        return {
            success: false,
            error: 'CAPTCHA expirat. Generați unul nou.'
        };
    }
    
    // Verifică numărul de încercări
    if (captcha.attempts >= 3) {
        activeCaptchas.delete(token);
        return {
            success: false,
            error: 'Prea multe încercări. Generați un CAPTCHA nou.'
        };
    }
    
    // Incrementează numărul de încercări
    captcha.attempts++;
    
    // Verifică răspunsul
    const isCorrect = answer.toString().trim() === captcha.answer.toString().trim();
    
    if (isCorrect) {
        // Șterge CAPTCHA-ul după verificarea reușită
        activeCaptchas.delete(token);
        return {
            success: true,
            message: 'CAPTCHA verificat cu succes'
        };
    } else {
        return {
            success: false,
            error: 'Răspuns incorect. Încercați din nou.',
            attemptsLeft: 3 - captcha.attempts
        };
    }
}

/**
 * Curăță CAPTCHA-urile expirate
 */
function cleanupExpiredCaptchas() {
    const now = new Date();
    for (const [token, captcha] of activeCaptchas.entries()) {
        if (now > captcha.expiresAt) {
            activeCaptchas.delete(token);
        }
    }
}

/**
 * Verifică dacă un token CAPTCHA este valid (nu expirat)
 * @param {string} token - Token-ul CAPTCHA
 * @returns {boolean} True dacă token-ul este valid
 */
function isCaptchaValid(token) {
    const captcha = activeCaptchas.get(token);
    if (!captcha) return false;
    
    if (new Date() > captcha.expiresAt) {
        activeCaptchas.delete(token);
        return false;
    }
    
    return true;
}

/**
 * Obține informațiile despre un CAPTCHA
 * @param {string} token - Token-ul CAPTCHA
 * @returns {Object|null} Informațiile despre CAPTCHA sau null
 */
function getCaptchaInfo(token) {
    const captcha = activeCaptchas.get(token);
    if (!captcha) return null;
    
    if (new Date() > captcha.expiresAt) {
        activeCaptchas.delete(token);
        return null;
    }
    
    return {
        question: captcha.question,
        type: captcha.type,
        expiresAt: captcha.expiresAt.toISOString(),
        attempts: captcha.attempts
    };
}

/**
 * Șterge un CAPTCHA
 * @param {string} token - Token-ul CAPTCHA
 */
function deleteCaptcha(token) {
    activeCaptchas.delete(token);
}

/**
 * Obține statistici despre CAPTCHA-uri
 * @returns {Object} Statistici
 */
function getCaptchaStats() {
    cleanupExpiredCaptchas();
    
    return {
        activeCaptchas: activeCaptchas.size,
        totalQuestions: captchaQuestions.length,
        lastCleanup: new Date().toISOString()
    };
}

// Curăță CAPTCHA-urile expirate la fiecare 5 minute
setInterval(cleanupExpiredCaptchas, 5 * 60 * 1000);

module.exports = {
    generateCaptcha,
    verifyCaptcha,
    isCaptchaValid,
    getCaptchaInfo,
    deleteCaptcha,
    getCaptchaStats
};
