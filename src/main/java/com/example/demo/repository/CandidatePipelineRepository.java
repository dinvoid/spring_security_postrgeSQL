package com.example.demo.repository;

import com.example.demo.models.CandidatePipeline;
import com.example.demo.models.enumeration.PipelineStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CandidatePipelineRepository extends JpaRepository<CandidatePipeline,Long> {
    @Query("SELECT COALESCE(MAX(c.position), 0) FROM CandidatePipeline c WHERE c.status = :status")
    Integer findMaxPositionByStatus(@Param("status") PipelineStatus status);
}
