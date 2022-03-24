import express from 'express';

import { createRoom, delRoom, getRooms,getRoom } from '../controllers/Room.js';
import { isLoggedIn, isValid } from '../middlewares/validity.js';


const router = express.Router();

router.get('/',isLoggedIn, getRooms);
router.get('/:roomId',isLoggedIn, getRoom);
router.post('/create', isLoggedIn, createRoom);

router.delete('/:roomId', isValid, isLoggedIn, delRoom);


export default router;