package com.example.demo.repository;

import com.example.demo.models.CandidatePipeline;
import com.example.demo.models.enumeration.PipelineStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CandidatePipelineRepository extends JpaRepository<CandidatePipeline,Long> {
    @Query("SELECT COALESCE(MAX(c.position), 0) FROM CandidatePipeline c WHERE c.status = :status")
    Integer findMaxPositionByStatus(@Param("status") PipelineStatus status);
    @Query("SELECT MAX(c.position) FROM CandidatePipeline c WHERE c.employerId = :emp AND c.status = :status")
    Integer findMaxPositionByEmployerIdAndStatus(@Param("emp") Long employerId, @Param("status") PipelineStatus status);


    boolean existsByEmployerIdAndCandidateId(Long emp, Long id);
    List<CandidatePipeline> findByStatusOrderByPositionAsc(PipelineStatus status);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM CandidatePipeline c WHERE c.status = :status AND c.employerId = :employerId ORDER BY c.position ASC")
    List<CandidatePipeline> findByStatusForUpdateOrderedAndEmployer(
            @Param("status") PipelineStatus status,
            @Param("employerId") Long employerId
    );
    List<CandidatePipeline> findByEmployerIdOrderByStatusAscPositionAsc(Long employerId);

}
