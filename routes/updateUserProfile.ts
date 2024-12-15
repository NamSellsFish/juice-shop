import { type Request, type Response, type NextFunction } from 'express'
import csrf from 'csurf'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

const csrfProtection = csrf({ cookie: true })

module.exports = function updateUserProfile() {
  return [csrfProtection, (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    const allowedOrigins = ['http://localhost:3000']

    if (!allowedOrigins.includes(req.headers.origin || '')) {
      return next(new Error('Invalid request origin'))
    }

    if (loggedInUser) {
      UserModel.findByPk(loggedInUser.data.id).then((user: UserModel | null) => {
        if (user != null) {
          challengeUtils.solveIf(challenges.csrfChallenge, () => {
            return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
              (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
              req.body.username !== user.username
          })

          void user.update({ username: req.body.username }).then((savedUser: UserModel | null) => {
            if (!savedUser) {
              throw new Error('User not found')
            }
            const updatedToken = security.authorize(savedUser.toJSON())
            security.authenticatedUsers.put(updatedToken, savedUser.toJSON())

            res.cookie('token', updatedToken, {
              httpOnly: true,
              secure: true,
              sameSite: 'strict'
            })
            res.location(process.env.BASE_PATH + '/profile')
            res.redirect(process.env.BASE_PATH + '/profile')
          })

        } else {
          next(new Error('User not found'))
        }
      }).catch((error: Error) => {
        next(error)
      })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }]
}