package com.example.demo.dto.request;
import lombok.Data;

import java.util.List;

@Data
public class CandidateSearchRequest {
    private String headline;               // search in headline, summary
    private List<String> skills;          // filter by skills
    private int page = 0;                 // pagination page
    private int size = 10;                // results per page
}
