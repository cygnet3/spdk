use bitcoin::OutPoint;
use psbt_v2::v2::{
    Constructor, Creator, Input, InputsOnlyModifiable, Output, OutputsOnlyModifiable,
};
use rand::seq::SliceRandom;

use crate::core::{Error, Psbt, Result};

pub trait ConstructorPsbtExt {
    fn create_new_transaction(outputs: Vec<Output>) -> Result<Self>
    where
        Self: Sized;

    fn add_inputs(self, selected_outpoints: Vec<OutPoint>) -> Result<Self>
    where
        Self: Sized;

    fn add_outputs(self, outputs: Vec<Output>) -> Result<Self>
    where
        Self: Sized;
}

impl ConstructorPsbtExt for Psbt {
    fn create_new_transaction(mut outputs: Vec<Output>) -> Result<Self> {
        // Randomize the order of the outputs
        outputs.shuffle(&mut rand::thread_rng());

        let mut constructor = Creator::new().constructor_modifiable();

        // add outputs
        for output in outputs {
            constructor = constructor.output(output);
        }

        Ok(constructor.psbt()?)
    }

    fn add_inputs(self, selected_outpoints: Vec<OutPoint>) -> Result<Self> {
        let mut constructor = Constructor::<InputsOnlyModifiable>::new(self)
            .map_err(|e| Error::Other(e.to_string()))?;

        // add inputs
        for outpoint in selected_outpoints {
            constructor = constructor.input(Input::new(&outpoint));
        }

        Ok(constructor.psbt()?)
    }

    fn add_outputs(self, outputs: Vec<Output>) -> Result<Self>
    where
        Self: Sized,
    {
        let mut constructor = Constructor::<OutputsOnlyModifiable>::new(self)
            .map_err(|e| Error::Other(e.to_string()))?;

        // add outputs
        for output in outputs {
            constructor = constructor.output(output);
        }

        Ok(constructor.psbt()?)
    }
}
