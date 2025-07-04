import React from "react";
import styles from "./GuardTagsDisplayer.module.css";

const GuardTagsDisplayer = ({ usesLLMs=true, multiTurn=false, singleTurn=false, custom=false, input=false, output=false }) => {
  return (
    <div className={styles.guardTagsDisplayer}>
      {usesLLMs && <div className={`${styles.pill} ${styles.usesLLM}`}>LLM-as-a-judge</div>}
      {multiTurn && <div className={`${styles.pill} ${styles.multiTurn}`}>Multi-turn</div>}
      {singleTurn && <div className={`${styles.pill} ${styles.singleTurn}`}>Single-turn</div>}
      {custom && <div className={`${styles.pill} ${styles.custom}`}>Custom</div>}
      {input && <div className={`${styles.pill} ${styles.input}`}>Input Guard</div>}
      {output && <div className={`${styles.pill} ${styles.output}`}>Output Guard</div>}
    </div>
  );
};

export default GuardTagsDisplayer;
