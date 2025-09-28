import bcrypt from 'bcrypt'
import httpStatus from 'http-status'
import jwt, { JwtPayload } from 'jsonwebtoken'
import config from '../../config'
import AppError from '../../errors/AppError'
import { sendEmail } from '../../utils/sendEmail'
import { OAuth2Client } from 'google-auth-library'
import { TLoginUser } from './auth.interface'
import { createToken, verifyToken } from './auth.utils'
import isPasswordMatched from '../../helpers/auth/isPasswordMatched'
import { User } from '../user/user.model'


const loginUser = async (payload: TLoginUser) => {
  // checking if the user is exist
  const user = await User.findOne({ email: payload.email })

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !')
  }

  // checking if the user is already deleted
  const isDeleted = user?.isDeleted

  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !')
  }

  // checking if the user is blocked
  const userStatus = user?.status

  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !')
  }

  //checking if the password is correct


  // TODO this functions isPasswordMatched ts error
  if (!(await isPasswordMatched(payload?.password, user.password!)))
    throw new AppError(httpStatus.FORBIDDEN, 'Password do not matched')

  //create token and sent to the  client

  const jwtPayload = {
    userId: user._id,
    role: user.role
  }

  const accessToken = createToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in as string
  )

  const refreshToken = createToken(
    jwtPayload,
    config.jwt_refresh_secret as string,
    config.jwt_refresh_expires_in as string
  )

  return {
    accessToken,
    refreshToken
  }
}



const changePassword = async (userData: JwtPayload, payload: { oldPassword: string; newPassword: string }) => {
  // checking if the user is exist
  const user = await User.findById(userData.userId)

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !')
  }
  // checking if the user is already deleted

  const isDeleted = user?.isDeleted

  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !')
  }

  // checking if the user is blocked

  const userStatus = user?.status

  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !')
  }

  //checking if the password is correct
  // TODO this functions isPasswordMatched ts error
  if (!(await isPasswordMatched(payload?.oldPassword, user.password!)))
    throw new AppError(httpStatus.FORBIDDEN, 'Password do not matched')

  //hash new password
  const newHashedPassword = await bcrypt.hash(payload.newPassword, Number(config.bcrypt_salt_rounds))

  await User.findOneAndUpdate(
    {
      _id: user._id,
      role: user.role
    },
    {
      password: newHashedPassword,
      passwordChangedAt: new Date()
    }
  )

  return null
}

const refreshToken = async (token: string) => {
  // checking if the given token is valid
  const decoded = verifyToken(token, config.jwt_refresh_secret as string)

  const { userId, iat } = decoded

  // checking if the user is exist
  const user = await User.findById(userId)

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !')
  }
  // checking if the user is already deleted
  const isDeleted = user?.isDeleted

  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !')
  }

  // checking if the user is blocked
  const userStatus = user?.status

  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !')
  }

  if (user.passwordChangedAt && User.isJWTIssuedBeforePasswordChanged(user.passwordChangedAt, iat as number)) {
    throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized !')
  }

  const jwtPayload = {
    userId: user._id,
    role: user.role
  }

  const accessToken = createToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in as string
  )

  return {
    accessToken
  }
}

const forgetPassword = async (userEmail: string) => {
  // checking if the user is exist
  const user = await User.findOne({ email: userEmail })

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !')
  }
  // checking if the user is already deleted
  const isDeleted = user?.isDeleted

  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !')
  }

  // checking if the user is blocked
  const userStatus = user?.status

  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !')
  }

  const jwtPayload = {
    userId: user._id,
    role: user.role
  }

  const resetToken = createToken(jwtPayload, config.jwt_reset_password_secret as string, config.reset_password_time as string)

  const resetUILink = `${config.reset_pass_ui_link}?token=${resetToken} `

  await sendEmail(
    user.email,
    `Hi ${user.name}, <br/><br/>

You recently requested to reset your password. <br/><br/>

Please click the link below to reset your password: <br/><br/>

<a href="${resetUILink}" 
   style="display:inline-block; padding:10px 20px; font-size:16px; 
          background-color:#4CAF50; color:#ffffff; text-decoration:none; 
          border-radius:5px;">
   Reset Password
</a> <br/><br/>


This link will expire in <strong>${config.reset_password_time?.slice(0, -1)} minutes</strong>. <br/><br/>

If you didn’t request this, you can safely ignore this email. <br/><br/><br/>

Best regards, <br/>
The Bangla Versity Team`
  )

  return null
}

const resetPassword = async (payload: { newPassword: string }, token: string) => {
  // checking if the user is exist

  const decoded = jwt.verify(token, config.jwt_reset_password_secret as string) as JwtPayload
  const user = await User.findById(decoded.userId)
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !')
  }
  // checking if the user is already deleted
  const isDeleted = user?.isDeleted

  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !')
  }

  // checking if the user is blocked
  const userStatus = user?.status

  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !')
  }


  //hash new password
  const newHashedPassword = await bcrypt.hash(payload.newPassword, Number(config.bcrypt_salt_rounds))

  await User.findOneAndUpdate(
    {
      _id: decoded.userId,
      role: decoded.role
    },
    {
      password: newHashedPassword,
      passwordChangedAt: new Date()
    }
  )
}


const googleLogin = async ({ idToken }: { idToken: string }) => {
  if (!idToken) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Google ID token is required');
  }

  const client = new OAuth2Client(config.google_id);

  // verify token
  const ticket = await client.verifyIdToken({
    idToken,
    audience: config.google_id as string,
  });

  const payload = ticket.getPayload();
  const email = payload?.email;
  const name = payload?.name?.trim() || 'Google User';

  if (!email) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      'We couldn’t access your email from Google. Please allow email access when signing in with Google and try again.'
    );
  }

  const profileImage = payload?.picture || null;

  // find existing user in MongoDB
  const existingUser = await User.findOne({ email });

  if (!existingUser) {
    // create new user (student)
    // hash default google password


    const newUserPayload = {
      email,
      name,
      role: 'user',
      isEmailVerified: true,
      password: 'google',
      profileImage: profileImage,
    };

    const createdUser = await User.create(newUserPayload);

    // If you have a separate Student model/collection, create it here.
    // import Student at top and uncomment below:
    // const [firstName, ...rest] = name.split(' ');
    // const lastName = rest.join(' ') || '';
    // await Student.create({ userId: createdUser._id, firstName, lastName, profileImage });

    // create tokens
    const jwtPayload = {
      userId: createdUser._id,
      role: 'student',
    };

    const accessToken = createToken(
      jwtPayload,
      config.jwt_access_secret as string,
      config.jwt_access_expires_in as string
    );

    const refreshToken = createToken(
      jwtPayload,
      config.jwt_refresh_secret as string,
      config.jwt_refresh_expires_in as string
    );

    return {
      accessToken,
      refreshToken,
      userId: createdUser._id,
      role: 'student',
    };
  }

  // existing user: validate status / deleted
  if (existingUser.isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted!');
  }

  if (existingUser.status !== 'active') {
    throw new AppError(httpStatus.FORBIDDEN, `This user is ${existingUser?.status}!`);
  }

  const jwtPayload = {
    userId: existingUser._id,
    role: existingUser.role,
  };

  const accessToken = createToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in as string
  );

  const refreshToken = createToken(
    jwtPayload,
    config.jwt_refresh_secret as string,
    config.jwt_refresh_expires_in as string
  );

  return {
    accessToken,
    refreshToken,
    userId: existingUser._id,
    role: existingUser.role,
  };
};

export const AuthServices = {
  loginUser,
  changePassword,
  refreshToken,
  forgetPassword,
  resetPassword,
  googleLogin
}
