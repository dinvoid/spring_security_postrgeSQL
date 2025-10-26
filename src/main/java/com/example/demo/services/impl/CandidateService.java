package com.example.demo.services.impl;

import com.example.demo.dto.request.CandidateRequest;
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

@Service
@RequiredArgsConstructor
public class CandidateService {

    private final CandidateRepository candidateRepository;
    private final UserRepository userRepository;



    // Create or update candidate profile
    public Candidate saveCandidate(CandidateRequest request) {

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
    }

    // Get candidate by ID
    public Optional<Candidate> getCandidateById(Long id) {
        return candidateRepository.findById(id);
    }

    // Get candidate by user
    public Optional<Candidate> getCandidateByUser(User user) {
        return candidateRepository.findByUser(user);
    }

    // Get all candidates (for employers)
    public List<Candidate> getAllCandidates() {
        return candidateRepository.findAll();
    }

    // Delete candidate
    public void deleteCandidate(Long id) {
        candidateRepository.deleteById(id);
    }
}
