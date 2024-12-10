import {asyncHandler} from "../utils/asyncHandler.js"
import{ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.models.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken";
import mongoose from "mongoose"

const generateAccessAndRefreshTokens= async(userId)=>{
    try{
        const user= await User.findById(userId)
        const accessToken= user.generateAccessToken()
        const refreshToken= user.generateRefreshToken()

        user.refreshToken=refreshToken
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken}

    }catch(error){
        throw new ApiError(500,"something went wrong while generating refresh and access token")
    }
}

const registerUser = asyncHandler( async (req,res)=>{
    // return res.status(200).json({
    //     message: "everything is running fine"
    // })

    //get user details from frontend
    //validation - not empty
    //check if user already exists: username, email
    //check for images, check for avatar
    //upload them to cloudinary, avatar
    //create user object - create entry in db
    //remove password and refresh token field from response
    //check for user creation
    //return response

    //declare data point for req body
    const {fullname,email, username,password}=req.body
    // console.log("email: ", email);

    // if(fullname===""){
    //     throw new ApiError(400,"fullname is required")
    // }

    //check validation field is empty or not
    // if(
    //     [fullname,email,username,password].some((field)=> field?.trim=="")
    // ){
    //     throw new ApiError(400, "all fields are required")
    // }

    if ([fullname, email, username, password].some((field) => field?.trim === "")) {
        throw new ApiError(400, "All fields are required");
    }
    
    
    //checking the user already exist or not
    //for finding user
    const existedUser= await User.findOne({
        $or: [{ username },{ email }]
    })

    //if we find then throw error if not then continue
    if(existedUser){
        throw new ApiError(409, "User with email or username already exists")
    }

    // console.log(req.files);
    
    //here we extract local path of avatar
    const avatarLocalPath= req.files?.avatar[0]?.path
    //const coverImageLocalPath= req.files?.coverImage[0]?.path;

    //here we extract local path of coverImage
    let coverImageLocalPath;

    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0 ){
        coverImageLocalPath=req.files.coverImage[0].path
    }

    //if avatar not found then show an error
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required")
    }

    //if avatar and coverImage found then upload it on cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage= await uploadOnCloudinary(coverImageLocalPath)

    //if avatar not uploading then throw error
    if(!avatar){
        throw new ApiError(400, "Avatar file is required")
    }

    //if everythind is fine then create an object of user and upload it to database
    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username:username.toLowerCase()
    })

    //leave password and token from received value due to security reason
    const createdUser= await User.findById(user._id).select(
        "-password -refreshToken"
    )

    //if user is not created then throw error
    if(!createdUser){
        throw new ApiError(500, "something went wrong while registering user")

    }

    //return if user created
    return res.status(201).json(
        new ApiResponse(200, createdUser,"User registered successfully")
    )

})

const loginUser= asyncHandler(async (req,res)=>{
    //req body->data
    //username or email
    //find the user
    //password check
    //access and refresh token generate
    //send cookies

    //take data from req.body
    const {email,username,password}=req.body

    //check username and email is in field
    if(!username && !email){
        throw new ApiError(400,"username or email is required")
    }

    // if(!(username || email)){
    //     throw new ApiError(400,"username or email is required")
    // }

    //check the username in db
    const user= await User.findOne({
        $or:[{username},{email}]
    })

    //if not found
    if(!user){
        throw new ApiError(404,"user does not exist")
    }

    const isPasswordValid= await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401,"Password is invalid")
    }

    const {accessToken,refreshToken}= await generateAccessAndRefreshTokens(user._id)

    const loggedInUser= await User.findById(user._id)
    .select("-password -refreshToken")

    const options= {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken,options)
    .cookie("refreshToken", refreshToken,options)
    .json(
        new ApiResponse(200,
            {
            user: loggedInUser, accessToken,refreshToken
            },
            "User Logged In Successfully"
        )
    )
})

const logoutUser= asyncHandler(async(req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken:undefined
            }
        },
        {
            new:true
        }
    )

    const options= {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User logged Out"))
})

const refreshAccesToken= asyncHandler(async(req,res)=>{

    const incomingRefreshToken=req.cookie.refreshToken || req.body.refreshAccesToken

    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized request")
    }

    try {
        const decodedToken=jwt.verify(
            incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET
        )
    
        const user= await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"Invalid refresh token")
        }
    
        if(incomingRefreshToken!==user?.refreshToken){
            throw new ApiError(401,"Refresh token is expired or used")
    
        }
    
        const options={
            httpOnly:true,
            secure:true
        }
    
        const {accessToken,newRefreshToken}=await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken,refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh Token")
    }
})

const changeCurrentPassword= asyncHandler(async(req,res)=>{
    const {oldPassword, newPassword}=req.body

    const user= User.findById(req.user?._id)
    const isPasswordCorrect=await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400,"Invalid old password")
    }

    user.password=newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {},"Password change successfully"))
})

const getCurrentUser= asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(200,req.user,"current user fetched successfully")
})

const updateAccountDetails= asyncHandler(async(req,res)=>{
    const{fullname,email}=req.body

    if(!fullname || !email){
        throw new ApiError(400,"All fields are required")
    }

    const user= User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                fullname,
                email
            }
        },
        {new:true}

    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,user,"Account details update successfully "))
})

const updateUserAvatar=asyncHandler(async(req,res)=>{
    const avatarLocalPath= req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is missing")
    }

    const avatar= await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user= await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar:avatar.url
            }
        },
        {new:true}
     ).select("-password")

     return res
     .status(200)
     .json(new ApiError(200,user,"Avatar is successfully updated"))
})

const updateUserCoverImage=asyncHandler(async(req,res)=>{
    const coverImageLocalPath= req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400,"Cover image file is missing")
    }

    const coverImage= await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading on cover image")
    }

    const user= await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage:coverImage.url
            }
        },
        {new:true}
     ).select("-password")

     return res
     .status(200)
     .json(new ApiResponse(200,user,"Cover Image updated successfully"))
})

const getUserChannelProfile= asyncHandler(async(req,res)=>{
    const {username}=req.params

    if(!username.trim()){
        throw new ApiError(400,"username is missing")
    }

    const channel= await User.aggregate([
        //these all are the pipeline, there are  5 pipelines below
        {   //matching user
            $match:{
                username: username?.toLowerCase()
            }
        },
        {   //counting subscriber through channel 
            $lookup:{
                from:"subscription",
                localField:"_id",
                foreignField:"channel",
                as:"subscribers"
            }
        },
        {   //counting how many channel i subcribed through subscriber
            $lookup:{
                from:"subscription",
                localField:"_id",
                foreignField:"subscriber",
                as:"subscribedTo"
            }
        },
        {   //subcribers count, channel subscribe, is subscribe or not?
            $addFields:{
                subcribersCount:{
                    $size:"$subscribers"
                },
                channelSubcribedToCount:{
                    $size:"$subscribedTo"
                },
                isSubscribed:{
                    $cond:{
                        if:{$in:[req.user?._id,"$subscribers.subcriber"]},
                        then:true,
                        else:false
                    }
                }
            }
        },
        {
            $project:{
                fullname:1,
                username:1,
                subcribersCount:1,
                channelSubcribedToCount:1, 
                isSubscribed:1,
                avatar:1,
                coverImage:1,
                email:1
            }
        }
    ])
    // console.log(channel)

    if(!channel?.length){
        throw new ApiError(404,"channel does not exists")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200,channel[0],"User channel fetched succesfully")
    )


})

const getWatchHistory= asyncHandler(async (req,res)=>{
    const user = await User.aggregate([
        {
            $match:{
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup:{
                from: "videos",
                localField:"watchHistory",
                foreignField:"_id",
                as: "watchHistory",
                pipeline:[
                    {
                        $lookup:{
                            from:"users",
                            localField:"owner",
                            foreignField:"_id",
                            as:"owner",
                            pipeline:[
                                {
                                    $project:{
                                        fullname:1,
                                        username:1,
                                        avatar:1
                                    }
                                },
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first:"$owner"
                            }
                        }
                    }
                ]

            }
        }    
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "watch history fetched successfully"
        )
    )
})


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccesToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}

