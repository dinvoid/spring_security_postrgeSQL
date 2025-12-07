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

    public int getNextPosition(PipelineStatus status) {
        int maxPosition = candidatePipelineRepository.findMaxPositionByStatus(status);
        return maxPosition + 1; // next position
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
        int position = getNextPosition(column);

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
    public CandidatePipelineResponse moveCards(MoveCardRequest request){
        // 1. Fetch the card
        CandidatePipeline card = candidatePipelineRepository.findById(request.getPipelineId())
                .orElseThrow(() -> new RuntimeException("Card not found"));

        // 2. Update status
        card.setStatus(request.getNewStatus());

        // 3. Update position in the column
        int newPos = request.getNewPosition();

        // Shift other cards if needed
        candidatePipelineRepository.findByStatusOrderByPositionAsc(request.getNewStatus())
                .forEach(c -> {
                    if(c.getPosition() >= newPos && !c.getId().equals(card.getId())){
                        c.setPosition(c.getPosition() + 1);
                    }
                });

        card.setPosition(newPos);

        // 4. Save changes
        CandidatePipeline updatedCard = candidatePipelineRepository.save(card);

        // 5. Return response
        return CandidatePipelineResponse.builder()
                .id(updatedCard.getId())
                .employer(updatedCard.getEmployerId())
                .candidate(updatedCard.getCandidateId())
                .status(updatedCard.getStatus())
                .position(updatedCard.getPosition())
                .build();
    }

    @Override
    @Transactional
    public CandidatePipelineResponse moveCard(MoveCardRequest req) {
        // Fetch the card and ensure it exists
        CandidatePipeline card = candidatePipelineRepository.findById(req.getPipelineId())
                .orElseThrow(() -> new RuntimeException("Card not found"));

        Long employerId = card.getEmployerId(); // only reorder this employer's cards

        PipelineStatus oldStatus = card.getStatus();
        int oldPos = card.getPosition();
        PipelineStatus newStatus = req.getNewStatus();
        int newPos = req.getNewPosition();

        // No changes, return immediately
        if (oldStatus == newStatus && oldPos == newPos) {
            return CandidatePipelineResponse.builder()
                    .id(card.getId())
                    .employer(card.getEmployerId())
                    .candidate(card.getCandidateId())
                    .status(card.getStatus())
                    .position(card.getPosition())
                    .build();
        }

        // Fetch columns filtered by employer
        List<CandidatePipeline> oldColumn = candidatePipelineRepository
                .findByStatusForUpdateOrderedAndEmployer(oldStatus, employerId);

        List<CandidatePipeline> newColumn = null;
        if (oldStatus != newStatus) {
            newColumn = candidatePipelineRepository
                    .findByStatusForUpdateOrderedAndEmployer(newStatus, employerId);
        }

        // Reordering logic
        if (oldStatus == newStatus) {
            if (newPos > oldPos) {
                for (CandidatePipeline c : oldColumn) {
                    int pos = c.getPosition();
                    if (pos > oldPos && pos <= newPos) {
                        c.setPosition(pos - 1);
                    }
                }
            } else {
                for (CandidatePipeline c : oldColumn) {
                    int pos = c.getPosition();
                    if (pos >= newPos && pos < oldPos) {
                        c.setPosition(pos + 1);
                    }
                }
            }
        } else {
            // Remove gap in old column
            for (CandidatePipeline c : oldColumn) {
                if (c.getPosition() > oldPos) {
                    c.setPosition(c.getPosition() - 1);
                }
            }

            // Make room in new column
            for (CandidatePipeline c : newColumn) {
                if (c.getPosition() >= newPos) {
                    c.setPosition(c.getPosition() + 1);
                }
            }
        }

        // Update moved card
        card.setStatus(newStatus);
        card.setPosition(newPos);

        // Save all updated cards
        candidatePipelineRepository.saveAll(oldColumn);
        if (newColumn != null) {
            candidatePipelineRepository.saveAll(newColumn);
        }

        CandidatePipeline saved = candidatePipelineRepository.save(card);

        // Return response
        return CandidatePipelineResponse.builder()
                .id(saved.getId())
                .employer(saved.getEmployerId())
                .candidate(saved.getCandidateId())
                .status(saved.getStatus())
                .position(saved.getPosition())
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


