# MODELS=(starcoder2-7b_16k starcoder2-15b_16k starcoderbase-3b starcoderbase-7b CodeLlama-7b-hf CodeLlama-13b-hf)
MODELS=(starcoderbase-3b deepseek-coder-1.3b-base)
MODES=(completion)

for model in ${MODELS[@]}; do
  for mode in ${MODES[@]}; do
    python mark_batch.py \
    -d data/scenario_dow.jsonl \
    -o generations_asleep_${mode}_${model}_results.jsonl \
    -j 10 \
    generations_asleep_${mode}_${model}.json
  done
done