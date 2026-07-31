import { ReactNode } from 'react';

function Highlight({children, color}:{children: ReactNode, color: string}) {
  return (
    <span style={{backgroundColor:color, padding:"4px 8px", display: "inline-block", fontSize: "0.8rem"}}>{children}</span>
  );
}

export default Highlight;
