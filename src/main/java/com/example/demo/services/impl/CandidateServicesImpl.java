package com.example.demo.services.impl;

import com.example.demo.dto.request.CandidateRequest;
import com.example.demo.dto.response.CandidateResponse;
import com.example.demo.exception.UnauthorizedActionException;
import com.example.demo.models.Candidate;
import com.example.demo.models.User;
import com.example.demo.repository.CandidateRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.jwt.SecurityUtils;
import com.example.demo.services.CandidateService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.service.annotation.PutExchange;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CandidateServicesImpl implements CandidateService {
    private final CandidateRepository candidateRepository;
    private final UserRepository userRepository;
    // Create or update candidate profile
    @Override
    public Candidate saveCandidate(CandidateRequest request){
    return null;
    }
    //update candidate

    @Override
    public CandidateResponse updateProfile(Long id,CandidateRequest request){
        // Fetch the candidate by the user ID
        Candidate candidate = candidateRepository.findByUserId(id)
                .orElseThrow(() -> new UnauthorizedActionException("Candidate not found"));
        // Update fields
        candidate.setFirstName(request.getFirstName());
        candidate.setLastName(request.getLastName());
        candidate.setHeadline(request.getHeadline());
        candidate.setSummary(request.getSummary());
        candidate.setSkills(request.getSkills());

        // Save updated candidate
        Candidate updatedCandidate = candidateRepository.save(candidate);

        // Build response DTO
        return CandidateResponse.builder()
                .firstName(updatedCandidate.getFirstName())
                .lastName(updatedCandidate.getLastName())
                .headline(updatedCandidate.getHeadline())
                .summary(updatedCandidate.getSummary())
                .skills(updatedCandidate.getSkills())
                .build();
    }
    @Override
    public CandidateResponse viewProfile(Long userId) {
        Candidate candidate = candidateRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Candidate not found"));

        User user = candidate.getUser(); // assuming Candidate has a User reference

        CandidateResponse response = new CandidateResponse();
        response.setUserId(candidate.getUser().getId());
        response.setFirstName(candidate.getFirstName());
        response.setLastName(candidate.getLastName());
        response.setHeadline(candidate.getHeadline());
        response.setSummary(candidate.getSummary());
        response.setSkills(candidate.getSkills());

        return response;
    }


    // Create or update candidate profile
   /* public Candidate saveCandidate(CandidateRequest request) {

        String loggedInEmail = SecurityUtils.getCurrentUsername();

        if (loggedInEmail == null) {
            throw new UnauthorizedActionException("You must be logged in to create a candidate profile.");
        }

        // Find the logged-in user
        User loggedInUser = userRepository.findByUsername(loggedInEmail)
                .orElseThrow(() -> new UnauthorizedActionException("User not found with email: " + loggedInEmail));

        // Prevent creating a candidate for a different user
        if (request.getUserId() != null && !loggedInUser.getId().equals(request.getUserId())) {
            throw new UnauthorizedActionException("You are not authorized to create a candidate for another user.");

        }
        Candidate candidate = Candidate.builder()
                .user(loggedInUser)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .headline(request.getHeadline())
                .summary(request.getSummary())
                .skills(request.getSkills())
                .build();
        return candidateRepository.save(candidate);
    } */
}
