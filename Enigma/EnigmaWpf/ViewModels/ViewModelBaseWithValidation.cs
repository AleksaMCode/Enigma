using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using GalaSoft.MvvmLight;

namespace Enigma.EnigmaWpf.ViewModels
{
    public abstract class ViewModelBaseWithValidation : ViewModelBase
    {
        protected IEnumerable<ValidationResult> ValidationErrors { get; set; }

        protected bool IsValid()
        {
            var ctx = new ValidationContext(this);
            var results = new List<ValidationResult>();

            if (!Validator.TryValidateObject(this, ctx, results, true))
            {
                ValidationErrors = results;
                return false;
            }

            ValidationErrors = null;
            return true;
        }
    }
}
