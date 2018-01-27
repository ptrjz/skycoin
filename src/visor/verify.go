package visor

import (
	"errors"
	"fmt"

	"github.com/skycoin/skycoin/src/coin"
	"github.com/skycoin/skycoin/src/util/fee"
)

/*

verify.go: Methods for handling transaction verification

There are two levels of transaction constraint: HARD and SOFT

HARD constraints can NEVER be violated. These include:
    - Malformed transaction
    - Double spends
        - NOTE: Double spend verification must be done against the unspent output set,
                the methods here do not operate on the unspent output set.
                They accept a `uxIn coin.UxArray` argument, which are the unspents associated
                with the transaction's inputs.  The unspents must be queried from the unspent
                output set first, thus if any unspent is not found for the input, it cannot be spent.

SOFT constraints are based upon mutable parameters. These include:
    - Max block size (transaction must not be larger than this value)
    - Insufficient coin hour burn fee
    - Timelocked distribution addresses
    - Decimal place restrictions

These methods should be called via the Blockchain object when possible,
using Blockchain.VerifyTransactionHardConstraints and Blockchain.VerifyTransactionAllConstraints,
since data from the blockchain and unspent output set are required to fully validate a transaction.

How soft and hard verification are applied:

- When adding a signed block from the network, HARD constraints are applied.
  Any block whose transactions violate HARD constraints will be rejected, regardless of the signature.
  This occurs in Blockchain.processTransactions().

- When creating a new block, HARD and SOFT constraints are applied to transactions before including them
  in the new block.
  Soft constraints are applied in Visor.CreateBlock().

- When adding a transaction to the unconfirmed transaction pool, HARD and SOFT constraints are applied.
    HARD and SOFT constraints are applied by Visor.InjectTransaction
    HARD constraints are applied by UnconfirmedTxnPool.InjectTransaction
- TODO: This policy should be changed to:
    - If the transaction violates HARD constraints, do not add it to the unconfirmed txn pool or broadcast it.
    - If the transaction only violates SOFT constraints, add it to the unconfirmed txn pool as an "invalid" txn, but do not broadcast it.
    - If the transaction has been invalid in the unconfirmed txn pool for too long, remove it.
    - Periodically check the invalid transactions in the unconfirmed txn pool for validity.
        - If one stops violating constraints, broadcast it.
        - If one begins violating HARD constraints, remove it.

*/

// ErrTransactionViolatesHardConstraint is returned when a transaction violates hard constraints
type ErrTransactionViolatesHardConstraint struct {
	Err error
}

// NewErrTransactionViolatesHardConstraint creates ErrTransactionViolatesHardConstraint
func NewErrTransactionViolatesHardConstraint(err error) error {
	if err == nil {
		return nil
	}
	return ErrTransactionViolatesHardConstraint{
		Err: err,
	}
}

func (e ErrTransactionViolatesHardConstraint) Error() string {
	return fmt.Sprintf("Transaction violates hard constraint: %v", e.Err)
}

// ErrTransactionViolatesSoftConstraint is returned when a transaction violates soft constraints
type ErrTransactionViolatesSoftConstraint struct {
	Err error
}

// NewErrTransactionViolatesSoftConstraint creates ErrTransactionViolatesSoftConstraint
func NewErrTransactionViolatesSoftConstraint(err error) error {
	if err == nil {
		return nil
	}
	return ErrTransactionViolatesSoftConstraint{
		Err: err,
	}
}

func (e ErrTransactionViolatesSoftConstraint) Error() string {
	return fmt.Sprintf("Transaction violates soft constraint: %v", e.Err)
}

// VerifyTransactionSoftConstraints returns an error if any "soft" constraint are violated.
// "soft" constaints are enforced at the network and block publication level,
// but are not enforced at the blockchain level.
// Clients will not accept blocks that violate hard constraints, but will
// accept blocks that violate soft constraints.
// Checks:
//      * That the transaction size is not greater than the max block total transaction size
//      * That the transaction burn enough coin hours (the fee)
//      * That if that transaction does not spend from a locked distribution address
//      * That the transaction does not create outputs with a higher decimal precision than is allowed
//      * That the transaction's total output hours do not overflow uint64 (this would be a hard constraint, but is here by necessity)
func VerifyTransactionSoftConstraints(txn coin.Transaction, headTime uint64, uxIn coin.UxArray, maxSize int) error {
	if err := verifyTransactionSoftConstraints(txn, headTime, uxIn, maxSize); err != nil {
		return NewErrTransactionViolatesSoftConstraint(err)
	}
	return nil
}

func verifyTransactionSoftConstraints(txn coin.Transaction, headTime uint64, uxIn coin.UxArray, maxSize int) error {
	if txn.Size() > maxSize {
		return errors.New("Transaction size bigger than max block size")
	}

	f, err := fee.TransactionFee(&txn, headTime, uxIn)
	if err != nil {
		return err
	}

	if err := fee.VerifyTransactionFee(&txn, f); err != nil {
		return err
	}

	if TransactionIsLocked(uxIn) {
		return errors.New("Transaction has locked address inputs")
	}

	// Reject transactions that do not conform to decimal restrictions
	for _, o := range txn.Out {
		if err := DropletPrecisionCheck(o.Coins); err != nil {
			return err
		}
	}

	// Verify CoinHours do not overflow
	// NOTE: This would be in the hard constraints, but a bug caused overflowing
	// coinhour transactions to be published. To avoid breaking the blockchain
	// sync, the rules are applied here.
	// If/when the blockchain is upgraded/reset, move this to the hard constraints.
	_, err = txn.OutputHours()
	return err
}

// VerifyTransactionHardConstraints returns an error if any "hard" constraints are violated.
// "hard" constraints are always enforced and if violated the transaction
// should not be included in any block and any block that includes such a transaction
// should be rejected.
// Checks:
//      * That the inputs to the transaction exist
//      * That the transaction does not create or destroy coins
//      * That the signatures on the transaction are valid
//      * That there are no duplicate ux inputs
//      * That there are no duplicate outputs
// NOTE: Double spends are checked against the unspent output pool when querying for uxIn
func VerifyTransactionHardConstraints(txn coin.Transaction, head *coin.SignedBlock, uxIn coin.UxArray) error {
	if err := verifyTransactionHardConstraints(txn, head, uxIn); err != nil {
		return NewErrTransactionViolatesHardConstraint(err)
	}
	return nil
}

func verifyTransactionHardConstraints(txn coin.Transaction, head *coin.SignedBlock, uxIn coin.UxArray) error {
	//CHECKLIST: DONE: check for duplicate ux inputs/double spending
	//     NOTE: Double spends are checked against the unspent output pool when querying for uxIn

	//CHECKLIST: DONE: check that inputs of transaction have not been spent
	//CHECKLIST: DONE: check there are no duplicate outputs

	// Q: why are coin hours based on last block time and not
	// current time?
	// A: no two computers will agree on system time. Need system clock
	// indepedent timing that everyone agrees on. fee values would depend on
	// local clock

	// Check transaction type and length
	// Check for duplicate outputs
	// Check for duplicate inputs
	// Check for invalid hash
	// Check for no inputs
	// Check for no outputs
	// Check for zero coin outputs
	// Check valid looking signatures

	if err := txn.Verify(); err != nil {
		return err
	}

	// Checks whether ux inputs exist,
	// Check that signatures are allowed to spend inputs
	if err := txn.VerifyInput(uxIn); err != nil {
		return err
	}

	uxOut := coin.CreateUnspents(head.Head, txn)

	// Check that there are any duplicates within this set
	// NOTE: This should already be checked by txn.Verify()
	if uxOut.HasDupes() {
		return errors.New("Duplicate output in transaction")
	}

	// Check that no coins are created or destroyed
	if err := coin.VerifyTransactionCoinsSpending(uxIn, uxOut); err != nil {
		return err
	}

	// Check that no hours are created
	// NOTE: this check doesn't catch overflow errors in the addition of hours
	// Some blocks had their hours overflow, and if this rule was checked here,
	// existing blocks would invalidate.
	// The hours overflow check is handled in the soft constraints for now.
	return coin.VerifyTransactionHoursSpending(head.Time(), uxIn, uxOut)
}
