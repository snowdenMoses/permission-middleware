import config from 'config';
import { NextFunction, Response } from 'express';
import jwt from 'jsonwebtoken';
import { HttpException } from '@exceptions/HttpException';
import { DataStoredInToken, RequestWithUser } from './auth.interface';
import employeeModel from '@models/employee/employee.model';


//The permission middleware should always come after the Authentication middleware (If there is any)

const READ = 1;
const WRITE = 2;
const UPDATE = 3;
const DELETE = 4;

export class userPermissions{
    permission: any;
    constructor(perm = 0){
        this.permission = perm
    }
    getAllPermissions(){
        return {
            Read: !!(this.permission & READ),
            Write: !!(this.permission & WRITE),
            Update: !!(this.permission & UPDATE),
            Delete: !!(this.permission & DELETE),
        }
    }
    addPermissions(perm){
      this.permission = this.permission | perm
    }
    removePermissions(perm){
      if(this.getAllPermissions()[perm]){
        this.permission = this.permission ^ perm
      }
    }
}

const permissionMiddleware = (dept) => {
    return  async (req: RequestWithUser, res: Response, next: NextFunction) =>{
        try {
          const Authorization = req.header('Authorization').split('Bearer ')[1] || null;
          console.log('-----------------------------------------------')
          if (Authorization) {
            const secretKey: string = config.get('secretKey');
            const verificationResponse = (await jwt.verify(Authorization, secretKey)) as DataStoredInToken;
            const userId = verificationResponse._id;
            const findUser = await (await employeeModel.findById(userId).populate('department designation')).toObject();
            const userDept = findUser.department
            console.log(findUser.department);
            console.log(findUser.designation);
            if(findUser.designation['designation'] === "SUPER"){
              req.user = findUser;
              console.log('HELLO SUPER')
              next();
            }else{
              console.log('your department', userDept['department']);
              if(userDept['department'] === dept){
                const permission = new userPermissions(Number(findUser.permissionLevel)).getAllPermissions()
                console.log(req.method)
                if(req.method === 'GET'){
                  if(permission.Read === true){
                    req.user = findUser;
                    next();
                  }else{
                    next(new HttpException(403, 'You have insufficient authorization level'));
                  }
  
                }else if(req.method === 'POST'){
                  console.log('POST REQUEST !!!!')
                  console.log('Permission', permission)
                  if(permission.Write === true){
                    req.user = findUser;
                    next();
                  }else{
                    next(new HttpException(403, 'You have insufficient authorization level'));
                  }
                }else if(req.method === 'PUT' || req.method === 'PATCH'){
                  if(permission.Update === true){
                    req.user = findUser;
                    next();
                  }else{
                    next(new HttpException(403, 'You have insufficient authorization level'));
                  }
  
                }else if(req.method === 'DELETE'){
                  if(permission.Delete === true){
                    req.user = findUser;
                    next();
                  }else{
                    next(new HttpException(401, 'You have insufficient authorization level'));
                  }
  
                }
  
              }else{
                next(new HttpException(403, 'this route is only accesible to ' + dept + ' users'))
              }
            }
          } else {
            next(new HttpException(404, 'Authentication token missing'));
          }
        } catch (error) {
          next(new HttpException(403, 'Wrong authentication token'));
        }
  
    }
  };
  
  export default permissionMiddleware;