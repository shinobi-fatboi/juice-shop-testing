/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import dataErasure from './routes/dataErasure'
import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import { sequelize } from './models'
import { UserModel } from './models/user'
import { QuantityModel } from './models/quantity'
import { CardModel } from './models/card'
import { PrivacyRequestModel } from './models/privacyRequests'
import { AddressModel } from './models/address'
import { SecurityAnswerModel } from './models/securityAnswer'
import { SecurityQuestionModel } from './models/securityQuestion'
import { RecycleModel } from './models/recycle'
import { ComplaintModel } from './models/complaint'
import { ChallengeModel } from './models/challenge'
import { BasketItemModel } from './models/basketitem'
import { FeedbackModel } from './models/feedback'
import { ProductModel } from './models/product'
import { WalletModel } from './models/wallet'
import logger from './lib/logger'
import config from 'config'
import path from 'path'
import morgan from 'morgan'
import colors from 'colors/safe'
import * as utils from './lib/utils'
import * as Prometheus from 'prom-client'
import datacreator from './data/datacreator'

import validatePreconditions from './lib/startup/validatePreconditions'
import cleanupFtpFolder from './lib/startup/cleanupFtpFolder'
import validateConfig from './lib/startup/validateConfig'
import restoreOverwrittenFilesWithOriginals from './lib/startup/restoreOverwrittenFilesWithOriginals'
import registerWebsocketEvents from './lib/startup/registerWebsocketEvents'
import customizeApplication from './lib/startup/customizeApplication'
import customizeEasterEgg from './lib/startup/customizeEasterEgg' // vuln-code-snippet hide-line

import authenticatedUsers from './routes/authenticatedUsers'

const startTime = Date.now()
const finale = require('finale-rest')
const express = require('express')
const compression = require('compression')
const helmet = require('helmet')
const featurePolicy = require('feature-policy')
const errorhandler = require('errorhandler')
const cookieParser = require('cookie-parser')
const serveIndex = require('serve-index')
const bodyParser = require('body-parser')
const cors = require('cors')
const securityTxt = require('express-security.txt')
const robots = require('express-robots-txt')
const yaml = require('js-yaml')
const swaggerUi = require('swagger-ui-express')
const RateLimit = require('express-rate-limit')
const ipfilter = require('express-ipfilter').IpFilter
const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'))
const {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
} = require('./routes/fileUpload')
const profileImageFileUpload = require('./routes/profileImageFileUpload')
const profileImageUrlUpload = require('./routes/profileImageUrlUpload')
const redirect = require('./routes/redirect')
const vulnCodeSnippet = require('./routes/vulnCodeSnippet')
const vulnCodeFixes = require('./routes/vulnCodeFixes')
const angular = require('./routes/angular')
const easterEgg = require('./routes/easterEgg')
const premiumReward = require('./routes/premiumReward')
const privacyPolicyProof = require('./routes/privacyPolicyProof')
const appVersion = require('./routes/appVersion')
const repeatNotification = require('./routes/repeatNotification')
const continueCode = require('./routes/continueCode')
const restoreProgress = require('./routes/restoreProgress')
const fileServer = require('./routes/fileServer')
const quarantineServer = require('./routes/quarantineServer')
const keyServer = require('./routes/keyServer')
const logFileServer = require('./routes/logfileServer')
const metrics = require('./routes/metrics')
const currentUser = require('./routes/currentUser')
const login = require('./routes/login')
const changePassword = require('./routes/changePassword')
const resetPassword = require('./routes/resetPassword')
const securityQuestion = require('./routes/securityQuestion')
const search = require('./routes/search')
const coupon = require('./routes/coupon')
const basket = require('./routes/basket')
const order = require('./routes/order')
const verify = require('./routes/verify')
const recycles = require('./routes/recycles')
const b2bOrder = require('./routes/b2bOrder')
const showProductReviews = require('./routes/showProductReviews')
const createProductReviews = require('./routes/createProductReviews')
const checkKeys = require('./routes/checkKeys')
const nftMint = require('./routes/nftMint')
const web3Wallet = require('./routes/web3Wallet')
const updateProductReviews = require('./routes/updateProductReviews')
const likeProductReviews = require('./routes/likeProductReviews')
const security = require('./lib/insecurity')
const app = express()
const server = require('http').Server(app)
const appConfiguration = require('./routes/appConfiguration')
const captcha = require('./routes/captcha')
const trackOrder = require('./routes/trackOrder')
const countryMapping = require('./routes/countryMapping')
const basketItems = require('./routes/basketItems')
const saveLoginIp = require('./routes/saveLoginIp')
const userProfile = require('./routes/userProfile')
const updateUserProfile = require('./routes/updateUserProfile')
const videoHandler = require('./routes/videoHandler')
const twoFactorAuth = require('./routes/2fa')
const languageList = require('./routes/languages')
const imageCaptcha = require('./routes/imageCaptcha')
const dataExport = require('./routes/dataExport')
const address = require('./routes/address')
const payment = require('./routes/payment')
const wallet = require('./routes/wallet')
const orderHistory = require('./routes/orderHistory')
const delivery = require('./routes/delivery')
const deluxe = require('./routes/deluxe')
const memory = require('./routes/memory')
const chatbot = require('./routes/chatbot')
const locales = require('./data/static/locales.json')
const i18n = require('i18n')
const antiCheat = require('./lib/antiCheat')



  app.use(bodyParser.urlencoded({ extended: true }))
  /* File Upload */
  app.post('/file-upload', uploadToMemory.single('file'), ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), handleZipFileUpload, checkUploadSize, checkFileType, handleXmlUpload)
  app.post('/profile/image/file', uploadToMemory.single('file'), ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), profileImageFileUpload())
  app.post('/profile/image/url', uploadToMemory.single('file'), profileImageUrlUpload())
  app.post('/rest/memories', uploadToDisk.single('image'), ensureFileIsPassed, security.appendUserId(), metrics.observeFileUploadMetricsMiddleware(), memory.addMemory())

  app.use(bodyParser.text({ type: '*/*' }))
  app.use(function jsonParser (req: Request, res: Response, next: NextFunction) {
    // @ts-expect-error FIXME intentionally saving original request in this property
    req.rawBody = req.body
    if (req.headers['content-type']?.includes('application/json')) {
      if (!req.body) {
        req.body = {}
      }
      if (req.body !== Object(req.body)) { // Expensive workaround for 500 errors during Frisby test run (see #640)
        req.body = JSON.parse(req.body)
      }
    }
    next()
  })

  /* HTTP request logging */
  const accessLogStream = require('file-stream-rotator').getStream({
    filename: path.resolve('logs/access.log'),
    frequency: 'daily',
    verbose: false,
    max_logs: '2d'
  })
  app.use(morgan('combined', { stream: accessLogStream }))

  // vuln-code-snippet start resetPasswordMortyChallenge
  /* Rate limiting */
  app.enable('trust proxy')
  app.use('/rest/user/reset-password', new RateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip } // vuln-code-snippet vuln-line resetPasswordMortyChallenge
  }))
  // vuln-code-snippet end resetPasswordMortyChallenge

  // vuln-code-snippet start changeProductChallenge
  /** Authorization **/
  /* Checks on JWT in Authorization header */ // vuln-code-snippet hide-line
  app.use(verify.jwtChallenges()) // vuln-code-snippet hide-line
  /* Baskets: Unauthorized users are not allowed to access baskets */
  app.use('/rest/basket', security.isAuthorized(), security.appendUserId())
  /* BasketItems: API only accessible for authenticated users */
  app.use('/api/BasketItems', security.isAuthorized())
  app.use('/api/BasketItems/:id', security.isAuthorized())
  /* Feedbacks: GET allowed for feedback carousel, POST allowed in order to provide feedback without being logged in */
  app.use('/api/Feedbacks/:id', security.isAuthorized())
  /* Users: Only POST is allowed in order to register a new user */
  app.get('/api/Users', security.isAuthorized())
  app.route('/api/Users/:id')
    .get(security.isAuthorized())
    .put(security.denyAll())
    .delete(security.denyAll())
  /* Products: Only GET is allowed in order to view products */ // vuln-code-snippet neutral-line changeProductChallenge
  app.post('/api/Products', security.isAuthorized()) // vuln-code-snippet neutral-line changeProductChallenge
  // app.put('/api/Products/:id', security.isAuthorized()) // vuln-code-snippet vuln-line changeProductChallenge
  app.delete('/api/Products/:id', security.denyAll())
  /* Challenges: GET list of challenges allowed. Everything else forbidden entirely */
  app.post('/api/Challenges', security.denyAll())
  app.use('/api/Challenges/:id', security.denyAll())
  /* Complaints: POST and GET allowed when logged in only */
  app.get('/api/Complaints', security.isAuthorized())
  app.post('/api/Complaints', security.isAuthorized())
  app.use('/api/Complaints/:id', security.denyAll())
  /* Recycles: POST and GET allowed when logged in only */
  app.get('/api/Recycles', recycles.blockRecycleItems())
  app.post('/api/Recycles', security.isAuthorized())
  /* Challenge evaluation before finale takes over */
  app.get('/api/Recycles/:id', recycles.getRecycleItem())
  app.put('/api/Recycles/:id', security.denyAll())
  app.delete('/api/Recycles/:id', security.denyAll())
  /* SecurityQuestions: Only GET list of questions allowed. */
  app.post('/api/SecurityQuestions', security.denyAll())
  app.use('/api/SecurityQuestions/:id', security.denyAll())
  /* SecurityAnswers: Only POST of answer allowed. */
  app.get('/api/SecurityAnswers', security.denyAll())
  app.use('/api/SecurityAnswers/:id', security.denyAll())
  /* REST API */
  app.use('/rest/user/authentication-details', security.isAuthorized())
  app.use('/rest/basket/:id', security.isAuthorized())
  app.use('/rest/basket/:id/order', security.isAuthorized())
  /* Challenge evaluation before finale takes over */ // vuln-code-snippet hide-start
  app.post('/api/Feedbacks', verify.forgedFeedbackChallenge())
  /* Captcha verification before finale takes over */
  app.post('/api/Feedbacks', captcha.verifyCaptcha())
  /* Captcha Bypass challenge verification */
  app.post('/api/Feedbacks', verify.captchaBypassChallenge())
  /* User registration challenge verifications before finale takes over */
  app.post('/api/Users', (req: Request, res: Response, next: NextFunction) => {
    if (req.body.email !== undefined && req.body.password !== undefined && req.body.passwordRepeat !== undefined) {
      if (req.body.email.length !== 0 && req.body.password.length !== 0) {
        req.body.email = req.body.email.trim()
        req.body.password = req.body.password.trim()
        req.body.passwordRepeat = req.body.passwordRepeat.trim()
      } else {
        res.status(400).send(res.__('Invalid email/password cannot be empty'))
      }
    }
    next()
  })
  app.post('/api/Users', verify.registerAdminChallenge())
  app.post('/api/Users', verify.passwordRepeatChallenge()) // vuln-code-snippet hide-end
  app.post('/api/Users', verify.emptyUserRegistration())
  /* Unauthorized users are not allowed to access B2B API */
  app.use('/b2b/v2', security.isAuthorized())
  /* Check if the quantity is available in stock and limit per user not exceeded, then add item to basket */
  app.put('/api/BasketItems/:id', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemUpdate())
  app.post('/api/BasketItems', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemAddition(), basketItems.addBasketItem())

const multer = require('multer')
const uploadToMemory = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200000 } })
const mimeTypeMap: any = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg'
}
const uploadToDisk = multer({
  storage: multer.diskStorage({
    destination: (req: Request, file: any, cb: any) => {
      const isValid = mimeTypeMap[file.mimetype]
      let error: Error | null = new Error('Invalid mime type')
      if (isValid) {
        error = null
      }
      cb(error, path.resolve('frontend/dist/frontend/assets/public/images/uploads/'))
    },
    filename: (req: Request, file: any, cb: any) => {
      const name = security.sanitizeFilename(file.originalname)
        .toLowerCase()
        .split(' ')
        .join('-')
      const ext = mimeTypeMap[file.mimetype]
      cb(null, name + '-' + Date.now() + '.' + ext)
    }
  })
})

const expectedModels = ['Address', 'Basket', 'BasketItem', 'Captcha', 'Card', 'Challenge', 'Complaint', 'Delivery', 'Feedback', 'ImageCaptcha', 'Memory', 'PrivacyRequestModel', 'Product', 'Quantity', 'Recycle', 'SecurityAnswer', 'SecurityQuestion', 'User', 'Wallet']
while (!expectedModels.every(model => Object.keys(sequelize.models).includes(model))) {
  logger.info(`Entity models ${colors.bold(Object.keys(sequelize.models).length.toString())} of ${colors.bold(expectedModels.length.toString())} are initialized (${colors.yellow('WAITING')})`)
}
logger.info(`Entity models ${colors.bold(Object.keys(sequelize.models).length.toString())} of ${colors.bold(expectedModels.length.toString())} are initialized (${colors.green('OK')})`)

// vuln-code-snippet start exposedMetricsChallenge
/* Serve metrics */
let metricsUpdateLoop: any
const Metrics = metrics.observeMetrics() // vuln-code-snippet neutral-line exposedMetricsChallenge
app.get('/metrics', metrics.serveMetrics()) // vuln-code-snippet vuln-line exposedMetricsChallenge
errorhandler.title = `${config.get<string>('application.name')} (Express ${utils.version('express')})`

export async function start (readyCallback?: () => void) {
  const datacreatorEnd = startupGauge.startTimer({ task: 'datacreator' })
  await sequelize.sync({ force: true })
  await datacreator()
  datacreatorEnd()
  const port = process.env.PORT ?? config.get('server.port')
  process.env.BASE_PATH = process.env.BASE_PATH ?? config.get('server.basePath')

  metricsUpdateLoop = Metrics.updateLoop() // vuln-code-snippet neutral-line exposedMetricsChallenge

  server.listen(port, () => {
    logger.info(colors.cyan(`Server listening on port ${colors.bold(`${port}`)}`))
    startupGauge.set({ task: 'ready' }, (Date.now() - startTime) / 1000)
    if (process.env.BASE_PATH !== '') {
      logger.info(colors.cyan(`Server using proxy base path ${colors.bold(`${process.env.BASE_PATH}`)} for redirects`))
    }
    registerWebsocketEvents(server)
    if (readyCallback) {
      readyCallback()
    }
  })

  void collectDurationPromise('customizeApplication', customizeApplication)() // vuln-code-snippet hide-line
  void collectDurationPromise('customizeEasterEgg', customizeEasterEgg)() // vuln-code-snippet hide-line
}

export function close (exitCode: number | undefined) {
  if (server) {
    clearInterval(metricsUpdateLoop)
    server.close()
  }
  if (exitCode !== undefined) {
    process.exit(exitCode)
  }
}
// vuln-code-snippet end exposedMetricsChallenge

// stop server on sigint or sigterm signals
process.on('SIGINT', () => { close(0) })
process.on('SIGTERM', () => { close(0) })
