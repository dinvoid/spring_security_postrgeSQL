package com.example.demo.services;


import com.example.demo.dto.response.CandidateResponse;
import com.example.demo.dto.response.CandidateResponseSearchParam;
import com.example.demo.dto.response.CandidateSearchResponse;

import java.util.List;

public interface EmployerCandidateServices {


    List<CandidateSearchResponse> getAllCandidateProfiles();
    List<CandidateResponseSearchParam>searchCandidatesByParam(String skill, String headline);
    //List<CandidateResponseSearchParam> getFavorites();
}

