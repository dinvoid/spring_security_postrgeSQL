package com.example.demo.services;

import com.example.demo.dto.request.CandidateRequest;
import com.example.demo.dto.response.CandidateResponse;
import com.example.demo.exception.UnauthorizedActionException;
import com.example.demo.models.Candidate;
import com.example.demo.models.User;
import com.example.demo.repository.CandidateRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.jwt.SecurityUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

public interface CandidateService {

    // Create or update candidate profile
    public Candidate saveCandidate(CandidateRequest request);

    public CandidateResponse updateProfile(Long id,CandidateRequest request);

    public CandidateResponse viewProfile(Long id);
}