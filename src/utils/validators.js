// src/utils/validators.js

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validateUrl = (url) => {
  try {
    new URL(url);
    return url.startsWith('http://') || url.startsWith('https://');
  } catch {
    return false;
  }
};

const validatePassword = (password) => {
  return password && password.length >= 6;
};

module.exports = {
  validateEmail,
  validateUrl,
  validatePassword
};
