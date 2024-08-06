const express= require('express')
const {generateRegistrationOptions,verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse} = require('@simplewebauthn/server')
const crypto=require("node:crypto");
const { error } = require('node:console');

if(!globalThis.crypto){
    globalThis.crypto=crypto;
}

const PORT =3001
const app = express();

app.use(express.static('./public'))

app.use(express.json())

const userStore ={};
const challengeStore={};
app.post('/register',(req,res) =>{
    const {username,password} = req.body
    const id =`user_${Date.now()}`

    const user ={
        id,username,password
    }
    userStore[id]=user

    return res.json({id})
})


app.post('/register-challenge' , async (req,res)=>{
    const {userId} =req.body
    if(!userStore[userId]) return res.status(404).json({error : 'user not found!'})
      const  user=userStore[userId]
         const challengePayload =await generateRegistrationOptions({
        rpID:'localhost',
        rpName:"my Local Machine",
        userName:user.username 
        })
        challengeStore[userId]=challengePayload.challenge
        return res.json({options:challengePayload})
})

app.post('/register-verify' , async (req,res)=>{
    const {userId,cred} =req.body
   // console.log(req.body)
    if(!userStore[userId]) return res.status(404).json({error : 'user not found!'})
        const  user=userStore[userId]
    const challenge=challengeStore[userId]

   const verifyResult= await verifyRegistrationResponse({
    expectedChallenge:challenge,
    expectedOrigin:'http://localhost:3001',
    expectedRPID:'localhost',
    response:cred,
   })

   if(! verifyResult.verified) return res.json({error:'could not verify'});
  //  console.log(verifyResult.registrationInfo)
   userStore[userId].passkey = verifyResult.registrationInfo
   return res.json({verify:true})

})

app.post('/login-challenge', async (req,res)=>{
    const {userId} =req.body
    if(!userStore[userId]) return res.status(404).json({error : 'user not found!'})
        const  user=userStore[userId]
    const opts =await generateAuthenticationOptions({
        rpID:'localhost',
        userVerification: 'preferred',
        allowCredentials: [],
    })
   // console.log(challengeStore[userId]);
    challengeStore[userId]=opts.challenge
   // console.log(challengeStore);
    
    return res.json({options:opts})
})

app.post('/login-verify' , async (req,res)=>{
    const {userId,cred} =req.body
    //console.log("check user  id",userId)
 //console.log(userStore)
    if(!userStore[userId]) return res.status(404).json({error : 'user not found!'})
    const  user=userStore[userId] 
    const challenge=challengeStore[userId]

   const verifyResult= await verifyAuthenticationResponse({
    expectedChallenge:challenge,
    expectedOrigin:'http://localhost:3001',
    expectedRPID:'localhost',
    response:cred,
    authenticator:user.passkey
   })
//console.log(user.passkey)
   if(!verifyResult.verified) return res.json({error:'could not verify'});
  //  console.log(verifyResult.registrationInfo)
   //userStore[userId].passkey = verifyResult.registrationInfo
   return res.json({success:true,userId})

})


app.listen(PORT,()=> console.log(`Server started on Port: ${PORT}`))