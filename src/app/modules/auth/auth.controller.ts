import httpStatus from 'http-status'
import config from '../../config'
import AppError from '../../errors/AppError'
import catchAsync from '../../utils/catchAsync'
import sendResponse from '../../utils/sendResponse'
import { AuthServices } from './auth.service'


const loginUser = catchAsync(async (req, res) => {
  const result = await AuthServices.loginUser(req.body)
  const { refreshToken, accessToken } = result

  res.cookie('refreshToken', refreshToken, {
    secure: config.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'none',
    maxAge: eval(config.refresh_token_cookie_expires_in as string)
  })

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User is logged in successfully!',
    data: {
      accessToken
    }
  })
})

const changePassword = catchAsync(async (req, res) => {
  const { ...passwordData } = req.body
  const result = await AuthServices.changePassword(req.user, passwordData)
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password is updated successfully!',
    data: result
  })
})

const refreshToken = catchAsync(async (req, res) => {
  const { refreshToken } = req.cookies
  const result = await AuthServices.refreshToken(refreshToken)

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Access token is retrieved successfully!',
    data: result
  })
})


const forgetPassword = catchAsync(async (req, res) => {
  const userEmail = req.body.email
  const result = await AuthServices.forgetPassword(userEmail)
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Reset link is generated successfully!',
    data: result
  })
})

const resetPassword = catchAsync(async (req, res) => {
  const token = req.headers.authorization

  if (!token) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Something went wrong !')
  }

  const result = await AuthServices.resetPassword(req.body, token)
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password reset successfully!',
    data: result
  })
})


const googleLogin = catchAsync(async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Google ID token is required');
  }

  const result = await AuthServices.googleLogin({ idToken });

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Google user logged in successfully!',
    data: result,
  });
});


export const AuthControllers = {
  loginUser,
  changePassword,
  refreshToken,
  forgetPassword,
  resetPassword,
  googleLogin
}
