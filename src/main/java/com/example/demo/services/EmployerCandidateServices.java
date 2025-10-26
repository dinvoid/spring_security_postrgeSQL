package com.example.demo.services;


import com.example.demo.dto.response.CandidateResponse;
import com.example.demo.dto.response.CandidateSearchResponse;

import java.util.List;

public interface EmployerCandidateServices {


    List<CandidateSearchResponse> getAllCandidateProfiles();
}

