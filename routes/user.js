import express from 'express';
import { userLogin, userSignup,changePassword } from '../controllers/User.js';
import { isLoggedIn } from '../middlewares/validity.js';
import { myRoom } from '../controllers/Room.js';

const router = express.Router();

router.post('/login', userLogin);
router.post('/signup', userSignup);
router.get('/myRoom',isLoggedIn, myRoom);
router.post('/changepassword', isLoggedIn, changePassword);


export default router;