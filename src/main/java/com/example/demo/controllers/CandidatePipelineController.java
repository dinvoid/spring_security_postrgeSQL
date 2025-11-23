package com.example.demo.controllers;

import com.example.demo.dto.response.CandidatePipelineResponse;
import com.example.demo.security.services.UserDetailsImpl;
import com.example.demo.services.CandidatePipelineServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
