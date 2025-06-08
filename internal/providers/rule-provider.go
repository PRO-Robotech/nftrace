package providers

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/PRO-Robotech/nftrace/internal/app"
	"github.com/PRO-Robotech/nftrace/pkg/watchers"

	"github.com/H-BF/corlib/logger"
	"github.com/Morwran/nft-go/pkg/nftenc"
	nftLib "github.com/google/nftables"
	"github.com/jellydator/ttlcache/v3"
)

type (
	RuleVal struct {
		Rule      *nftLib.Rule
		Human     string
		At        time.Time
		isRemoved bool
	}
	RuleKey struct {
		TableName   string
		TableFamily nftLib.TableFamily
		ChainName   string
		Handle      uint64
	}
)

var _ RuleProvider = (*ruleProvider)(nil)

type ruleProvider struct {
	cache  *ttlcache.Cache[RuleKey, RuleVal]
	cancel context.CancelFunc

	lastErr atomic.Value
}

func NewRuleProvider(ctx context.Context, useLogging bool) (*ruleProvider, error) {
	const ttl = 3 * time.Second

	cache := ttlcache.New(
		ttlcache.WithTTL[RuleKey, RuleVal](ttl),
	)

	cache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[RuleKey, RuleVal]) {
		if reason != ttlcache.EvictionReasonExpired {
			return
		}
		val := item.Value()
		if val.isRemoved && (time.Since(val.At) >= ttl) {
			return
		}
		cache.Set(item.Key(), item.Value(), ttl)
	})

	ctx, cancel := context.WithCancel(ctx)

	if !useLogging {
		logger.ToContext(ctx, app.NopLogger())
	}

	rp := &ruleProvider{
		cache:  cache,
		cancel: cancel,
	}

	if err := rp.refreshCache(); err != nil {
		cancel()
		return nil, err
	}

	go rp.run(ctx)

	return rp, nil
}

func (rp *ruleProvider) GetHumanRule(key RuleKey) (string, error) {
	if err, ok := rp.lastErr.Load().(error); ok && err != nil {
		return "", err
	}

	item := rp.cache.Get(key)

	if item == nil {
		rule, err := rp.findRule(key)
		if err != nil {
			return "", err
		}
		humanRule, err := nftenc.NewRuleEncoder(rule).Format()
		if err != nil {
			return "", err
		}
		item = rp.cache.Set(key, RuleVal{
			Rule:  rule,
			Human: humanRule,
			At:    time.Now(),
		}, ttlcache.DefaultTTL)
	}
	val := item.Value()
	if val.isRemoved || val.At.After(time.Now()) ||
		!val.EqKey(key) {
		return "", ErrRuleIsExpired
	}
	return val.Human, nil
}

func (rp *ruleProvider) Close() error {
	rp.cancel()
	return nil
}

func (rp *ruleProvider) findRule(key RuleKey) (*nftLib.Rule, error) {
	tbl, chain, handle := key.TableName, key.ChainName, key.Handle
	conn, err := nftLib.New()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.CloseLasting() }()
	rules, err := conn.GetRules(
		&nftLib.Table{
			Name:   tbl,
			Family: key.TableFamily,
		},
		&nftLib.Chain{Name: chain},
	)
	if err != nil {
		return nil, err
	}
	var rl *nftLib.Rule
	for _, rule := range rules {
		if rule.Handle == handle {
			rl = rule
			break
		}
	}

	if rl == nil {
		return nil, ErrRuleNotFound
	}

	return rl, nil
}

func (rp *ruleProvider) run(ctx context.Context) {
	go rp.cache.Start()
	defer rp.cache.Stop()

	ruleWatcher, err := watchers.RuleWatcher()
	if err != nil {
		rp.fatal(err)
		return
	}
	defer func() { _ = ruleWatcher.Close() }()
	log := logger.FromContext(ctx).Named("rule-provider")
	log.Info("started, listening for rule changes")
	defer log.Info("stopped")

	for stm := ruleWatcher.Stream(ctx); ; {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-stm:
			if !ok {
				rp.fatal(errors.New("netlink: stream closed"))
				return
			}
			if msg.Err != nil {
				rp.fatal(fmt.Errorf("receive netlink error message: %w", msg.Err))
				return
			}
			log.Debugf("received rule event: %s", msg.Evt.ActionInfo())
			human, err := nftenc.NewRuleEncoder(msg.Evt.Val).Format()
			if err != nil {
				rp.fatal(fmt.Errorf("failed to format rule: %w", err))
				return
			}

			rp.cache.Set(
				RuleKey{
					TableName:   msg.Evt.Val.Table.Name,
					TableFamily: msg.Evt.Val.Table.Family,
					ChainName:   msg.Evt.Val.Chain.Name,
					Handle:      msg.Evt.Val.Handle,
				},
				RuleVal{
					Rule:      msg.Evt.Val,
					Human:     human,
					At:        time.Now(),
					isRemoved: msg.Evt.Action == watchers.RmAction,
				},
				ttlcache.DefaultTTL,
			)
		}
	}
}

func (rp *ruleProvider) fatal(err error) {
	rp.lastErr.Store(err)
	rp.cancel()
}

func (rp *ruleProvider) refreshCache() error {
	conn, err := nftLib.New()
	if err != nil {
		return fmt.Errorf("new netlink connection: %w", err)
	}
	defer func() { _ = conn.CloseLasting() }()

	rules, err := conn.GetAllRules()
	if err != nil {
		return fmt.Errorf("failed to obtain rules from the netfilter: %w", err)
	}
	t := time.Now()
	for _, rl := range rules {
		humanRule, err := nftenc.NewRuleEncoder(rl).Format()
		if err != nil {
			return fmt.Errorf("failed to format rule %d: %w", rl.Handle, err)
		}
		rp.cache.Set(
			RuleKey{
				TableName:   rl.Table.Name,
				TableFamily: rl.Table.Family,
				ChainName:   rl.Chain.Name,
				Handle:      rl.Handle,
			},
			RuleVal{
				Rule:  rl,
				Human: humanRule,
				At:    t,
			}, ttlcache.DefaultTTL)
	}
	return nil
}

func (rv *RuleVal) EqKey(key RuleKey) bool {
	return rv.Rule != nil && rv.Rule.Table.Name == key.TableName &&
		rv.Rule.Chain.Name == key.ChainName &&
		rv.Rule.Handle == key.Handle
}

var (
	ErrRuleNotFound  = errors.New("provider can't find a rule")
	ErrRuleIsExpired = errors.New("rule is old or expired")
)
