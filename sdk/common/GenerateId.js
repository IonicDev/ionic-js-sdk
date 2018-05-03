/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * GenerateId module.
 * @module generateId
 */
module.exports = { generateId };

/**
 * generate a random int to use as a message id
 *
 * maxint supported by PNaCl is 2147483647,
 * so we use a range between 1 and 2147483647
 * @return {number} int id
 */
function generateId() {
    return Math.floor((Math.random() * 2147483646) + 1);
}
