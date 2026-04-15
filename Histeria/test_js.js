// Test JavaScript syntax for quiz editor
let quizQuestions = [{ type: 'test', question: '', correct_answer: '', wrong_answers: ['', '', ''] }];
let currentQuestionIndex = 0;

const openQuizEditor = () => {
  const existingQuiz = document.getElementById('quiz-questions').value;
  if (existingQuiz.trim()) {
    try {
      quizQuestions = JSON.parse(existingQuiz);
    } catch (e) {
      quizQuestions = [{ type: 'test', question: '', correct_answer: '', wrong_answers: ['', '', ''] }];
    }
  } else {
    quizQuestions = [{ type: 'test', question: '', correct_answer: '', wrong_answers: ['', '', ''] }];
  }
  currentQuestionIndex = 0;
  console.log('Quiz editor opened');
};

const closeQuizEditor = () => {
  console.log('Quiz editor closed');
};

const renderQuizTabs = () => {
  console.log('Tabs rendered');
};

const switchQuestion = (index) => {
  console.log('Switched to question', index);
};

const loadQuestion = (index) => {
  console.log('Loaded question', index);
};

const saveCurrentQuestion = () => {
  console.log('Question saved');
};

const updateQuestionTypeUI = (type) => {
  console.log('UI updated for type', type);
};

const addQuestion = () => {
  console.log('Question added');
};

const deleteQuestion = () => {
  console.log('Question deleted');
};

const saveQuiz = () => {
  console.log('Quiz saved');
};

console.log('JavaScript syntax test passed');