package com.example.demo.services;

import com.example.demo.payload.request.LoginRequest;
import com.example.demo.payload.request.SignupRequest;
import com.example.demo.exception.response.JwtResponse;

public interface AuthServices {
   public void registerUser(SignupRequest signupRequest);
   public JwtResponse authenticateUser(LoginRequest loginRequest);

}
