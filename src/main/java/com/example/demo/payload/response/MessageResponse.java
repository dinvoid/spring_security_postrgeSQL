package com.example.demo.payload.response;

public class MessageResponse {
    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    String message;
    public MessageResponse(String message){
        this.message=message;
    }
}
