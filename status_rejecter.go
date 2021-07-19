package cel

import (
	"fmt"
	"time"
	"net/http"

	"github.com/devopsfaith/krakend-cel/internal"
	"github.com/google/cel-go/cel"
	"github.com/luraproject/lura/config"
	"github.com/luraproject/lura/logging"
)

func NewStatusRejecter(l logging.Logger, cfg *config.EndpointConfig) *StatusRejecter {
	def, ok := internal.ConfigGetter(cfg.ExtraConfig)
	if !ok {
		return nil
	}

	p := internal.NewCheckExpressionParser(l)
	evaluators, err := p.ParseJWT(def)
	if err != nil {
		l.Debug("CEL: error building the JWT rejecter:", err.Error())
		return nil
	}

	statuses := make([]int, len(def))
	for i, d := range def {
		if d.CheckStatus > 0 {
			statuses[i] = d.CheckStatus
		} else {
			statuses[i] = http.StatusUnauthorized
		}
	}

	return &StatusRejecter{
		name:       cfg.Endpoint,
		evaluators: evaluators,
		statuses:     statuses,
		logger:     l,
	}
}

type StatusRejecter struct {
	name       string
	evaluators []cel.Program
	statuses   []int
	logger     logging.Logger
}

func (r *StatusRejecter) Reject(data map[string]interface{}) (bool, int) {
	now := timeNow().Format(time.RFC3339)
	reqActivation := map[string]interface{}{
		internal.JwtKey: data,
		internal.NowKey: now,
	}
	for i, eval := range r.evaluators {
		res, _, err := eval.Eval(reqActivation)
		resultMsg := fmt.Sprintf("CEL: %s rejecter #%d result: %v - err: %v", r.name, i, res, err)

		if v, ok := res.Value().(bool); !ok || !v {
			r.logger.Info(resultMsg)
			return true, r.statuses[i]
		}
		r.logger.Debug(resultMsg)
	}
	return false, 0
}
