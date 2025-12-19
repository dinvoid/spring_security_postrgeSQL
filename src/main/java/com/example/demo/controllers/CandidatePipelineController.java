package com.example.demo.controllers;

import com.example.demo.dto.request.MoveCardRequest;
import com.example.demo.dto.response.CandidatePipelineResponse;
import com.example.demo.security.services.UserDetailsImpl;
import com.example.demo.services.CandidatePipelineServices;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/kanban")
public class CandidatePipelineController {
    @Autowired
    private CandidatePipelineServices srv;
    @PreAuthorize("hasRole('MODERATOR')")
    @PostMapping("/new")
    public ResponseEntity<CandidatePipelineResponse> addToKanban(@AuthenticationPrincipal UserDetailsImpl emp,Long candidate){
        CandidatePipelineResponse cpr=srv.addToKanban(emp.getId(),candidate);
        return ResponseEntity.ok(cpr);
    }
    @PreAuthorize("hasRole('MODERATOR')")
    @PatchMapping("/move")
    public ResponseEntity<CandidatePipelineResponse> moveCard(@Valid @RequestBody MoveCardRequest request) {
        CandidatePipelineResponse updatedCard = srv.moveCard(request);
        return ResponseEntity.ok(updatedCard);
    }
    @PreAuthorize("hasRole('MODERATOR')")
    @GetMapping("/employer/{employerId}")
    public ResponseEntity<List<CandidatePipelineResponse>> getCardsByEmployer(
            @PathVariable("employerId") Long employerId) {
        List<CandidatePipelineResponse> cards = srv.getAllCardsByEmployer(employerId);
        return ResponseEntity.ok(cards);
    }
}
