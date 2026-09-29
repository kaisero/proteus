package simulate

import (
	"context"
	"fmt"
	"time"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/runlog"
)

// Step is one stage's work over a simulation's state. It returns what the stage
// concluded; the stepper records it.
type Step[S any] struct {
	Name, Slug string
	Do         func(ctx context.Context, s *S) (Outcome, error)
}

// Outcome is what one step concluded.
type Outcome struct {
	Fidelity   Fidelity
	Detail     string
	Unresolved []index.Unresolved
	// Candidates is the candidate set after this stage; nil when the stage does not
	// narrow it, and the previous count carries forward.
	Candidates *roaring.Bitmap
	// Debug lines go to the run log at debug level only: the rules left, the zone
	// placements, whatever explains the stage.
	Debug []string
}

// Execute runs the steps in order, recording a Stage for each and logging it.
//
// A step that declares no fidelity fails the run: a stage that does not say how
// certain it is makes every later certainty meaningless (spec §11.2). A step error
// is wrapped as kind/slug and stops the run. A cancelled context stops before the
// next step.
func Execute[S any](ctx context.Context, kind string, state *S, steps []Step[S], keepBitmaps bool, log *runlog.Logger) ([]Stage, error) {
	var stages []Stage
	var count uint64
	for _, st := range steps {
		if err := ctx.Err(); err != nil {
			return stages, fmt.Errorf("%s/%s: %w", kind, st.Slug, err)
		}
		start := time.Now()
		out, err := st.Do(ctx, state)
		stage := Stage{
			Name: st.Name, Slug: st.Slug, Fidelity: out.Fidelity, Detail: out.Detail,
			Unresolved: out.Unresolved, Elapsed: time.Since(start),
		}
		if err == nil && !out.Fidelity.Declared() {
			err = fmt.Errorf("stage declared no fidelity")
		}
		if err != nil {
			stage.Err = fmt.Errorf("%s/%s: %w", kind, st.Slug, err)
			stages = append(stages, stage)
			log.Errorf(runlog.TagStep, "%s/%s: failed: %v", kind, st.Slug, err)
			return stages, stage.Err
		}
		if out.Candidates != nil {
			count = out.Candidates.GetCardinality()
			if keepBitmaps {
				stage.State.Bitmap = out.Candidates.Clone()
			}
		}
		stage.State.Candidates = count
		stages = append(stages, stage)
		log.Infof(runlog.TagStep, "%s/%s: %s, %d candidates, %s - %s", kind, st.Slug, stage.Fidelity, count,
			stage.Elapsed.Round(time.Microsecond), stage.Detail)
		for _, u := range out.Unresolved {
			log.Infof(runlog.TagStep, "%s/%s: unresolved: %s", kind, st.Slug, u)
		}
		for _, d := range out.Debug {
			log.Debugf(runlog.TagStep, "%s/%s: %s", kind, st.Slug, d)
		}
	}
	return stages, nil
}

// Overall is the weakest fidelity of a run's stages.
func Overall(stages []Stage) Fidelity {
	fs := make([]Fidelity, len(stages))
	for i, s := range stages {
		fs[i] = s.Fidelity
	}
	return Weakest(fs...)
}
