/**
 * Security question options for account recovery. Must match mobile constants.
 * @module constants/securityQuestions
 */
const SECURITY_QUESTIONS = [
  { id: 'mother_maiden', text: "What is your mother's maiden name?" },
  { id: 'birth_city', text: 'What city were you born in?' },
  { id: 'first_pet', text: "What was the name of your first pet?" },
  { id: 'first_school', text: "What was your first school's name?" },
  { id: 'favorite_teacher', text: "What is your favorite teacher's name?" },
];

function getQuestionById(id) {
  return SECURITY_QUESTIONS.find((q) => q.id === id);
}

function normalizeAnswer(answer) {
  return String(answer || '').trim().toLowerCase();
}

module.exports = { SECURITY_QUESTIONS, getQuestionById, normalizeAnswer };
