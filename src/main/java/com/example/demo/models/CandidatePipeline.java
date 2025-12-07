package com.example.demo.models;

import com.example.demo.models.enumeration.PipelineStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Table(name = "candidate_pipeline")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CandidatePipeline{
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "employer_id", nullable = false)
    private Long employerId;

    @Column(name = "candidate_id", nullable = false)
    private Long candidateId;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PipelineStatus status = PipelineStatus.NEW;

    /** ordering inside a column for kanban */
    @Column(nullable = false)
    private Integer position = 0;

    @Column(columnDefinition = "text")
    private String notes;
    @Builder.Default
    @Column(name = "created_at", updatable = false)
    private LocalDate createdAt = LocalDate.now();

    @Builder.Default
    @Column(name = "updated_at")
    private LocalDate updatedAt = LocalDate.now();

    @PreUpdate
    public void touch() { this.updatedAt = LocalDate.now(); }

}
