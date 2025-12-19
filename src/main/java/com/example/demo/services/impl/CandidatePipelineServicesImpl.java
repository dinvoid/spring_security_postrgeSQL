package com.example.demo.services.impl;

import com.example.demo.dto.request.MoveCardRequest;
import com.example.demo.dto.response.CandidatePipelineResponse;
import com.example.demo.exception.AlreadyExistsException;
import com.example.demo.exception.response.MessageResponse;
import com.example.demo.models.Candidate;
import com.example.demo.models.CandidatePipeline;
import com.example.demo.models.User;
import com.example.demo.models.enumeration.PipelineStatus;
import com.example.demo.repository.CandidatePipelineRepository;
import com.example.demo.repository.CandidateRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.services.CandidatePipelineServices;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
@AllArgsConstructor
@Service
public class CandidatePipelineServicesImpl implements CandidatePipelineServices {

    private CandidatePipelineRepository candidatePipelineRepository;
    private UserRepository userRepository;
    private CandidateRepository candidateRepository;

    public int getNextPosition(Long emp, PipelineStatus status) {
        Integer  maxPosition = candidatePipelineRepository.findMaxPositionByEmployerIdAndStatus( emp,status);
        return (maxPosition!=null) ? maxPosition+1: 1; // next position
    }


    @Override
    public CandidatePipelineResponse addToKanban(@RequestParam Long emp, @RequestParam Long candidate) {
        boolean exist= candidatePipelineRepository.existsByEmployerIdAndCandidateId(emp, candidate);
       // boolean applicant=candidateRepository.findByUserId(candidate);
        Optional<Candidate> applicant=candidateRepository.findByUserId(candidate);

        if (exist) {
            throw new AlreadyExistsException("Candidate is already in favorites!");
        }
        if(applicant.isEmpty()){
            throw new RuntimeException("Not applicant");
        }


        PipelineStatus column = PipelineStatus.NEW; // example
        int position = getNextPosition(emp, column);

        CandidatePipeline pipeline = CandidatePipeline.builder()
                .employerId(emp)
                .candidateId(candidate)
                .position(position)
                .build();

        CandidatePipeline saved = candidatePipelineRepository.save(pipeline);

        return CandidatePipelineResponse.builder()
                .id(saved.getId())
                .employer(emp)
                .candidate(saved.getCandidateId())
                .position(saved.getPosition())
                .status(column)
                .build();
    }

    @Override
    @Transactional
    public CandidatePipelineResponse moveCard(MoveCardRequest req) {

        // 1. Fetch the card
        CandidatePipeline card = candidatePipelineRepository.findById(req.getPipelineId())
                .orElseThrow(() -> new RuntimeException("Card not found"));

        Long employerId = card.getEmployerId();
        PipelineStatus oldStatus = card.getStatus();
        int oldPos = card.getPosition();
        PipelineStatus newStatus = req.getNewStatus();
        int newPos = req.getNewPosition();

        // 2. No changes needed
        if (oldStatus == newStatus && oldPos == newPos) {
            return buildResponse(card);
        }

        // 3. Load columns
        List<CandidatePipeline> oldColumn = safeList(
                candidatePipelineRepository.findByStatusForUpdateOrderedAndEmployer(oldStatus, employerId)
        );

        List<CandidatePipeline> newColumn = (oldStatus == newStatus)
                ? oldColumn
                : safeList(candidatePipelineRepository.findByStatusForUpdateOrderedAndEmployer(newStatus, employerId));
        if (oldStatus != newStatus && newColumn.isEmpty()) {
            newPos = 1;
        }
        // 4. Perform reordering
        if (oldStatus == newStatus) {
            reorderWithinSameColumn(oldColumn, oldPos, newPos);
        } else {
            closeGapInOldColumn(oldColumn, oldPos);
            makeRoomInNewColumn(newColumn, newPos);
        }

        // 5. Update moved card
        card.setStatus(newStatus);
        card.setPosition(newPos);

        // 6. Save changes
        candidatePipelineRepository.saveAll(oldColumn);
        if (oldColumn != newColumn) candidatePipelineRepository.saveAll(newColumn);
        CandidatePipeline saved = candidatePipelineRepository.save(card);

        return buildResponse(saved);
    }
    private List<CandidatePipeline> safeList(List<CandidatePipeline> list) {
        return list == null ? new ArrayList<>() : list;
    }
    private void reorderWithinSameColumn(List<CandidatePipeline> column, int oldPos, int newPos) {
        if (newPos > oldPos) {
            for (CandidatePipeline c : column) {
                int pos = c.getPosition();
                if (pos > oldPos && pos <= newPos) {
                    c.setPosition(pos - 1);
                }
            }
        } else {
            for (CandidatePipeline c : column) {
                int pos = c.getPosition();
                if (pos >= newPos && pos < oldPos) {
                    c.setPosition(pos + 1);
                }
            }
        }
    }
    private void closeGapInOldColumn(List<CandidatePipeline> oldColumn, int oldPos) {
        for (CandidatePipeline c : oldColumn) {
            if (c.getPosition() > oldPos) {
                c.setPosition(c.getPosition() - 1);
            }
        }
    }
    private void makeRoomInNewColumn(List<CandidatePipeline> newColumn, int newPos) {
        for (CandidatePipeline c : newColumn) {
            if (c.getPosition() >= newPos) {
                c.setPosition(c.getPosition() + 1);
            }
        }
    }
    private CandidatePipelineResponse buildResponse(CandidatePipeline c) {
        return CandidatePipelineResponse.builder()
                .id(c.getId())
                .employer(c.getEmployerId())
                .candidate(c.getCandidateId())
                .status(c.getStatus())
                .position(c.getPosition())
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public List<CandidatePipelineResponse> getAllCardsByEmployer(Long employerId) {
        List<CandidatePipeline> cards = candidatePipelineRepository
                .findByEmployerIdOrderByStatusAscPositionAsc(employerId);

        List<CandidatePipelineResponse> response = new ArrayList<>();
        for (CandidatePipeline c : cards) {
            CandidatePipelineResponse dto = CandidatePipelineResponse.builder()
                    .id(c.getId())
                    .employer(c.getEmployerId())
                    .candidate(c.getCandidateId())
                    .status(c.getStatus())
                    .position(c.getPosition())
                    .build();
            response.add(dto);
        }

        return response;
    }

}


