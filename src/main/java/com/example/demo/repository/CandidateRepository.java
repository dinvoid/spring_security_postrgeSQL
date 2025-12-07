package com.example.demo.repository;

import com.example.demo.dto.response.CandidateResponse;
import com.example.demo.dto.response.CandidateResponseSearchParam;
import com.example.demo.models.Candidate;
import com.example.demo.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CandidateRepository extends JpaRepository<Candidate,Long> {
    Optional<Candidate> findByUser(User user);
    Optional<Candidate> findByUserId(Long userId);


    //List<Candidate> findByFavoriteTrue();

    //search candidate by params input
    @Query(value = """
        SELECT 
            u.id AS userId,
            c.first_name AS firstName,
            c.last_name AS lastName,
            c.headline AS headline,
            c.summary AS summary,
            CAST(c.skills AS TEXT) AS skills
        FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN candidates c ON u.id = c.user_id
        WHERE 
            (:skill IS NULL OR CAST(c.skills AS TEXT) LIKE CONCAT('%', :skill, '%'))
            or (:headline IS NULL OR c.headline LIKE CONCAT('%', :headline, '%'))
     
        """, nativeQuery = true)
    List<CandidateResponseSearchParam> searchCandidatesByParam(
            @Param("skill") String skill,
            @Param("headline") String headline
    );
    //search all candidate
    @Query(value = """
        SELECT 
            u.id AS userId,
            c.first_name AS firstName,
            c.last_name AS lastName,
            c.headline AS headline,
            c.summary AS summary,
            CAST(c.skills AS TEXT) AS skills
        FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN candidates c ON u.id = c.user_id
        """, nativeQuery = true)
    List<Object[]> findAllCandidateProfiles();


}
