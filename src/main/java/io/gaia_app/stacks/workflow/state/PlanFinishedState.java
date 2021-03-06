package io.gaia_app.stacks.workflow.state;

import io.gaia_app.stacks.bo.JobStatus;
import io.gaia_app.stacks.bo.Step;
import io.gaia_app.stacks.bo.StepType;
import io.gaia_app.stacks.workflow.JobWorkflow;
import io.gaia_app.stacks.bo.JobStatus;
import io.gaia_app.stacks.bo.Step;
import io.gaia_app.stacks.bo.StepType;
import io.gaia_app.stacks.workflow.JobWorkflow;

/**
 * Describes a job which plan has been finished
 */
public class PlanFinishedState implements JobState {
    @Override
    public void apply(JobWorkflow jobWorkflow) {
        var job = jobWorkflow.getJob();
        job.proceed(JobStatus.APPLY_STARTED);

        var step = new Step(StepType.APPLY, job.getId());
        job.getSteps().add(step);
        jobWorkflow.setCurrentStep(step);
        step.start();

        jobWorkflow.setState(new ApplyStartedState());
    }
}
