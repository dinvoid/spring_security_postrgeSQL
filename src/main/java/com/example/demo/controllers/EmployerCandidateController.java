package com.example.demo.controllers;

import com.example.demo.dto.response.CandidateResponse;
import com.example.demo.dto.response.CandidateSearchResponse;
import com.example.demo.services.EmployerCandidateServices;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/employer/candidates")
@RequiredArgsConstructor
public class EmployerCandidateController {
    @Autowired
    private final EmployerCandidateServices ec;

    /**
     * Search candidates with optional filters: skills, education, keyword
     */
    @PreAuthorize("hasRole('MODERATOR')")
    @GetMapping("/candidates")
    public ResponseEntity<List<CandidateSearchResponse>> getAllCandidates() {
        List<CandidateSearchResponse> candidates = ec.getAllCandidateProfiles();
        return ResponseEntity.ok(candidates);
    }

  /*  public ResponseEntity<List<CandidateResponse>> searchCandidates(
            @RequestParam(required = false) String skill,
            @RequestParam(required = false) String headline
    ) {
        List<CandidateResponse> candidates = employerCandidateServices.searchCandidates(skill,summary);
        return ResponseEntity.ok();
        //return ResponseEntity.ok(" g",""
                //employerCandidateServices.searchCandidates(skill, headline)
        //);
    }

   */
}
