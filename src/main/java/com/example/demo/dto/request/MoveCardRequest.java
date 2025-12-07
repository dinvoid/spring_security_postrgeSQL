package com.example.demo.dto.request;

import com.example.demo.models.enumeration.PipelineStatus;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MoveCardRequest {

    @NotNull
    private Long pipelineId; // The card ID

    @NotNull
    private PipelineStatus newStatus; // NEW, INTERVIEW, HIRED

    @NotNull
    private Integer newPosition; // 1 for top, 2 for second, etc.
}
