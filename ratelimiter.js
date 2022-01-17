const ratelimit = require('express-rate-limit')

const rateLimiter = (limit,timeFrameInMinutes)=>{
    return ratelimit({
        max:limit,
        windowMs:timeFrameInMinutes* 60*1000,
        message:{
            error:{
                status:429,
                message:"Too many messages",
                expiry:timeFrameInMinutes,

            }
        }
    })
}
module.exports =rateLimiter;