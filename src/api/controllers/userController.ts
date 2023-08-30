import {
  addUser,
  deleteUser,
  getAllUsers,
  getUser,
  updateUser,
} from '../models/userModel';
import {Request, Response, NextFunction} from 'express';
import CustomError from '../../classes/CustomError';
import bcrypt from 'bcryptjs';
import {User} from '../../interfaces/User';
import {PostUser} from '../../interfaces/User';
import { validationResult } from 'express-validator';
const salt = bcrypt.genSaltSync(12);

const userListGet = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const users = await getAllUsers();
    res.json(users);
  } catch (error) {
    next(error);
  }
};

const userGet = async (
  req: Request<{id: string}, {}, {}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await getUser(req.params.id);
    res.json(user);
  } catch (error) {
    next(error);
  }
};

// TDOD: create userPost function to add new user
// userPost should use addUser function from userModel
// userPost should use validationResult to validate req.body
// userPost should use bcrypt to hash password
const userPost = async (
  req: Request<{}, {}, PostUser>,
  res: Response,
  next: NextFunction
) => {
  try {
    if(!validationResult(req.body).isEmpty()) {
      throw new CustomError('Invalid input', 400);
    }
    req.body.password = bcrypt.hashSync(req.body.password, salt);
    const user_id = await addUser(req.body);
    res.json({
      message: 'user added',
      user_id: user_id,
    });
  }catch (error) {
    next(error);
  }
};

const userPut = async (
  req: Request<{id: number}, {}, User>,
  res: Response,
  next: NextFunction
) => {
  try {
    if ((req.user as User).role !== 'admin') {
      throw new CustomError('Admin only', 403);
    }

    const user = req.body;

    const result = await updateUser(user, req.params.id);
    if (result) {
      res.json({
        message: 'user modified',
      });
    }
  } catch (error) {
    next(error);
  }
};

// TODO: create userPutCurrent function to update current user
// userPutCurrent should use updateUser function from userModel
// userPutCurrent should use validationResult to validate req.body
const userPutCurrent = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = req.body
    if(validationResult(req.body).isEmpty()) {
      const result = await updateUser(user, (req.user as User).user_id);
      if (result) {
        res.json({
          message: 'user modified',
        });
      }
    } else {
      throw new CustomError('Invalid input', 400);
    }
  } catch(error) {
    next(error);
  }
};

// TODO: create userDelete function for admin to delete user by id
// userDelete should use deleteUser function from userModel
// userDelete should use validationResult to validate req.params.id
// userDelete should use req.user to get role
const userDelete = async (
  req: Request<{id: number}>,
  res: Response,
  next: NextFunction
) => {
  try {
    if((req.user as User).role !== 'admin') {
      throw new CustomError('Admin only', 403);
    }
    if(validationResult(req.body).isEmpty()) {
      const result = await deleteUser(req.params.id);
     } else {
        throw new CustomError('Invalid input', 400);
      }
  } catch(error) {
    next(error);
  }
}

const userDeleteCurrent = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const result = await deleteUser((req.user as User).user_id);
    if (result) {
      res.json({
        message: 'user deleted',
      });
    }
  } catch (error) {
    next(error);
  }
};

const checkToken = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user) {
    next(new CustomError('token not valid', 403));
  } else {
    res.json(req.user);
  }
};

export {
  userListGet,
  userGet,
  userPost,
  userPut,
  userPutCurrent,
  userDelete,
  userDeleteCurrent,
  checkToken,
};
