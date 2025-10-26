package com.example.demo.dto.response;

import lombok.Builder;
import lombok.Data;


public interface CandidateResponseSearchParam {
    Long getUserId();
    String getFirstName();
    String getLastName();
    String getHeadline();
    String getSummary();
    String getSkills();
}